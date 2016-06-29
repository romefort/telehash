#include "telehash.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "telehash.h" // util_sort(), util_sys_short()
#include "telehash.h" // e3x_rand()
#include "telehash.h"
#include "telehash.h"
#include "telehash.h"

lob_t lob_new()
{
  lob_t p;
  if(!(p = malloc(sizeof (struct lob_struct)))) return LOG("OOM");
  memset(p,0,sizeof (struct lob_struct));
  if(!(p->raw = malloc(2))) return lob_free(p);
  memset(p->raw,0,2);
//  LOG("LOB++ %p",p);
  return p;
}

lob_t lob_copy(lob_t p)
{
  lob_t np;
  np = lob_parse(lob_raw(p), lob_len(p));
  return np;
}

lob_t lob_unlink(lob_t parent)
{
  lob_t child;
  if(!parent) return NULL;
  child = parent->chain;
  parent->chain = NULL;
  return child;
}

lob_t lob_link(lob_t parent, lob_t child)
{
  if(!parent) parent = lob_new();
  if(!parent) return NULL;
  if(parent->chain) lob_free(parent->chain);
  parent->chain = child;
  if(child && child->chain == parent) child->chain = NULL;
  return parent;
}

lob_t lob_chain(lob_t p)
{
  lob_t np = lob_new();
  if(!np) return NULL;
  np->chain = p;
  return np;
}

lob_t lob_linked(lob_t parent)
{
  if(!parent) return NULL;
  return parent->chain;
}

lob_t lob_free(lob_t p)
{
  if(!p) return NULL;
  if(p->next) LOG("possible mem leak, lob is in a list: %s->%s",lob_json(p),lob_json(p->next));
//  LOG("LOB-- %p",p);
  if(p->chain) lob_free(p->chain);
  if(p->cache) free(p->cache);
  if(p->raw) free(p->raw);
  free(p);
  return NULL;
}

uint8_t *lob_raw(lob_t p)
{
  if(!p) return NULL;
  return p->raw;
}

size_t lob_len(lob_t p)
{
  if(!p) return 0;
  return 2+p->head_len+p->body_len;
}

lob_t lob_parse(const uint8_t *raw, size_t len)
{
  lob_t p;
  uint16_t nlen, hlen;
  size_t jtest;

  // make sure is at least size valid
  if(!raw || len < 2) return NULL;
  memcpy(&nlen,raw,2);
  hlen = util_sys_short(nlen);
  if(hlen > len-2) return NULL;

  // copy in and update pointers
  p = lob_new();
  if(!(p->raw = realloc(p->raw,len))) return lob_free(p);
  memcpy(p->raw,raw,len);
  p->head_len = hlen;
  p->head = p->raw+2;
  p->body_len = len-(2+p->head_len);
  p->body = p->raw+(2+p->head_len);

  // validate any json
  jtest = 0;
  if(p->head_len >= 7) js0n("\0",1,(char*)p->head,p->head_len,&jtest);
  if(jtest) return lob_free(p);

  return p;
}

uint8_t *lob_head(lob_t p, uint8_t *head, size_t len)
{
  uint16_t nlen;
  void *ptr;
  if(!p) return NULL;

  // new space and update pointers
  if(!(ptr = realloc(p->raw,2+len+p->body_len))) return NULL;
  p->raw = (uint8_t *)ptr;
  p->head = p->raw+2;
  p->body = p->raw+(2+len);
  // move the body forward to make space
  memmove(p->body,p->raw+(2+p->head_len),p->body_len);
  // copy in new head
  if(head) memcpy(p->head,head,len);
  else memset(p->head,0,len); // helps with debugging
  p->head_len = len;
  nlen = util_sys_short((uint16_t)len);
  memcpy(p->raw,&nlen,2);
  free(p->cache);
  p->cache = NULL;
  return p->head;
}

uint8_t *lob_body(lob_t p, uint8_t *body, size_t len)
{
  void *ptr;
  if(!p) return NULL;
  if(!(ptr = realloc(p->raw,2+len+p->head_len))) return NULL;
  p->raw = (uint8_t *)ptr;
  p->head = p->raw+2;
  p->body = p->raw+(2+p->head_len);
  if(body) memcpy(p->body,body,len); // allows lob_body(p,NULL,100) to allocate space
  else memset(p->body,0,len); // helps with debugging
  p->body_len = len;
  return p->body;
}

lob_t lob_append(lob_t p, uint8_t *chunk, size_t len)
{
  void *ptr;
  if(!p || !chunk || !len) return LOG("bad args");
  if(!(ptr = realloc(p->raw,2+len+p->body_len+p->head_len))) return NULL;
  p->raw = (unsigned char *)ptr;
  p->head = p->raw+2;
  p->body = p->raw+(2+p->head_len);
  memcpy(p->body+p->body_len,chunk,len);
  p->body_len += len;
  return p;
}

lob_t lob_append_str(lob_t p, char *chunk)
{
  if(!p || !chunk) return LOG("bad args");
  return lob_append(p, (uint8_t*)chunk, strlen(chunk));
}

size_t lob_head_len(lob_t p)
{
  if(!p) return 0;
  return p->head_len;
}

uint8_t *lob_head_get(lob_t p)
{
  if(!p) return NULL;
  return p->head;
}

size_t lob_body_len(lob_t p)
{
  if(!p) return 0;
  return p->body_len;
}

uint8_t *lob_body_get(lob_t p)
{
  if(!p) return NULL;
  return p->body;
}

// TODO allow empty val to remove existing
lob_t lob_set_raw(lob_t p, char *key, size_t klen, char *val, size_t vlen)
{
  char *json, *at, *eval;
  size_t len, evlen;

  if(!p || !key || !val) return LOG("bad args (%d,%d,%d)",p,key,val);
  if(p->head_len < 2) lob_head(p, (uint8_t*)"{}", 2);
  // convenience
  if(!klen) klen = strlen(key);
  if(!vlen) vlen = strlen(val);

  // make space and copy
  if(!(json = malloc(klen+vlen+p->head_len+4))) return LOG("OOM");
  memcpy(json,p->head,p->head_len);

  // if it's already set, replace the value
  eval = js0n(key,klen,json,p->head_len,&evlen);
  if(eval)
  {
    // looks ugly, but is just adjusting the space avail for the value to the new size
    // if existing was in quotes, include them
    if(*(eval-1) == '"')
    {
      eval--;
      evlen += 2;
    }
    memmove(eval+vlen,eval+evlen,(json+p->head_len) - (eval+evlen)); // frowney face
    memcpy(eval,val,vlen);
    len = p->head_len - evlen;
    len += vlen;
  }else{
    at = json+(p->head_len-1); // points to the "}"
    // if there's other keys already, add comma
    if(p->head_len >= 7)
    {
      *at = ','; at++;
    }
    *at = '"'; at++;
    memcpy(at,key,klen); at+=klen;
    *at = '"'; at++;
    *at = ':'; at++;
    memcpy(at,val,vlen); at+=vlen;
    *at = '}'; at++;
    len = (size_t)(at - json);
  }
  lob_head(p, (uint8_t*)json, len);
  free(json);
  return p;
}

lob_t lob_set_printf(lob_t p, char *key, const char *format, ...)
{
  va_list ap, cp;
  char *val;

  if(!p || !key || !format) return LOG("bad args");

  va_start(ap, format);
  va_copy(cp, ap);

  vasprintf(&val, format, ap);

  va_end(ap);
  va_end(cp);
  if(!val) return NULL;

  lob_set(p, key, val);
  free(val);
  return p;
}

lob_t lob_set_int(lob_t p, char *key, int val)
{
  char num[32];
  if(!p || !key) return LOG("bad args");
  sprintf(num,"%d",val);
  lob_set_raw(p, key, 0, num, 0);
  return p;
}

lob_t lob_set_uint(lob_t p, char *key, unsigned int val)
{
  char num[32];
  if(!p || !key) return LOG("bad args");
  sprintf(num,"%u",val);
  lob_set_raw(p, key, 0, num, 0);
  return p;
}

// embedded friendly float to string, printf float support is a morass
lob_t lob_set_float(lob_t p, char *key, float value, uint8_t places)
{
  int digit;
  float tens = 0.1;
  int tenscount = 0;
  int i;
  float tempfloat = value;
  char buf[16];

  if(!p || !key) return LOG("bad args");
  
  buf[0] = 0; // reset

  float d = 0.5;
  if(value < 0) d *= -1.0;
  for(i = 0; i < places; i++) d/= 10.0;
  tempfloat +=  d;

  if(value < 0) tempfloat *= -1.0;
  while((tens * 10.0) <= tempfloat)
  {
    tens *= 10.0;
    tenscount += 1;
  }

  if(value < 0) sprintf(buf+strlen(buf),"-");

  if(tenscount == 0) sprintf(buf+strlen(buf),"0");

  for(i=0; i< tenscount; i++)
  {
    digit = (int) (tempfloat/tens);
    sprintf(buf+strlen(buf),"%d",digit);
    tempfloat = tempfloat - ((float)digit * tens);
    tens /= 10.0;
  }

  if(places > 0)
  {
    sprintf(buf+strlen(buf),".");

    for(i = 0; i < places; i++) {
      tempfloat *= 10.0;
      digit = (int) tempfloat;
      sprintf(buf+strlen(buf),"%d",digit);
      tempfloat = tempfloat - (float) digit;
    }
  }

  lob_set_raw(p, key, 0, buf, 0);
  return p;
}

lob_t lob_set(lob_t p, char *key, char *val)
{
  if(!val) return LOG("bad args");
  return lob_set_len(p, key, 0, val, strlen(val));
}

lob_t lob_set_len(lob_t p, char *key, size_t klen, char *val, size_t vlen)
{
  char *escaped;
  size_t i, len;
  if(!p || !key || !val) return LOG("bad args");
  // TODO escape key too
  if(!(escaped = malloc(vlen*2+2))) return LOG("OOM"); // enough space worst case
  len = 0;
  escaped[len++] = '"';
  for(i=0;i<vlen;i++)
  {
    if(val[i] == '"' || val[i] == '\\') escaped[len++]='\\';
    escaped[len++]=val[i];
  }
  escaped[len++] = '"';
  lob_set_raw(p, key, klen, escaped, len);
  free(escaped);
  return p;
}

lob_t lob_set_base32(lob_t p, char *key, uint8_t *bin, size_t blen)
{
  char *val;
  if(!p || !key || !bin || !blen) return LOG("bad args");
  size_t vlen = base32_encode_length(blen)-1; // remove the auto-added \0 space
  if(!(val = malloc(vlen+2))) return LOG("OOM"); // include surrounding quotes
  val[0] = '"';
  base32_encode(bin, blen, val+1,vlen+1);
  val[vlen+1] = '"';
  lob_set_raw(p,key,0,val,vlen+2);
  free(val);
  return p;
}

// creates cached string on lob
char *lob_cache(lob_t p, size_t len)
{
  if(!p) return NULL;
  if(p->cache) free(p->cache);
  if(!(p->cache = malloc(len+1))) return LOG("OOM");
  p->cache[0] = 0; // flag
  return p->cache+1;
}

// return null-terminated json string
char *lob_json(lob_t p)
{
  if(!p) return NULL;
  if(p->head_len < 2) return NULL;
  // direct/internal use of cache
  if(!lob_cache(p,p->head_len)) return LOG("OOM");
  memcpy(p->cache,p->head,p->head_len);
  p->cache[p->head_len] = 0;
  return p->cache;
}


// unescape any json string in place
char *unescape(lob_t p, char *start, size_t len)
{
  char *str, *cursor;

  if(!p || !start || len <= 0) return NULL;

  // make a fresh cache if we haven't yet or was used external
  if(!p->cache || p->cache[0] == 0) lob_json(p);
  if(!p->cache) return NULL;

  // switch pointer to the json copy
  start = p->cache + (start - (char*)p->head);

  // terminate it
  start[len] = 0;

  // unescape it in place in the copy
  for(cursor=str=start; *cursor; cursor++,str++)
  {
    if(*cursor == '\\' && *(cursor+1) == 'n')
    {
      *str = '\n';
      cursor++;
    }else if(*cursor == '\\' && *(cursor+1) == '"'){
      *str = '"';
      cursor++;
    }else{
      *str = *cursor;
    }
  }
  *str = *cursor; // copy null terminator too
  return start;
}

char *lob_get(lob_t p, char *key)
{
  char *val;
  size_t len = 0;
  if(!p || !key || p->head_len < 5) return NULL;
  val = js0n(key,0,(char*)p->head,p->head_len,&len);
  return unescape(p,val,len);
}

char *lob_get_raw(lob_t p, char *key)
{
  char *val;
  size_t len = 0;
  if(!p || !key || p->head_len < 5) return NULL;
  val = js0n(key,0,(char*)p->head,p->head_len,&len);
  if(!val) return NULL;
  // if it's a string value, return start of quotes
  if(*(val-1) == '"') return val-1;
  // everything else is straight up
  return val;
}

size_t lob_get_len(lob_t p, char *key)
{
  char *val;
  size_t len = 0;
  if(!p || !key || p->head_len < 5) return 0;
  val = js0n(key,0,(char*)p->head,p->head_len,&len);
  if(!val) return 0;
  // if it's a string value, include quotes
  if(*(val-1) == '"') return len+2;
  // everything else is straight up
  return len;
}

int lob_get_int(lob_t p, char *key)
{
  char *val = lob_get(p,key);
  if(!val) return 0;
  return (int)strtol(val,NULL,10);
}

unsigned int lob_get_uint(lob_t p, char *key)
{
  char *val = lob_get(p,key);
  if(!val) return 0;
  return (unsigned int)strtoul(val,NULL,10);
}

float lob_get_float(lob_t p, char *key)
{
  char *val = lob_get(p,key);
  if(!val) return 0;
  return strtof(val,NULL);
}

// returns ["0","1","2"]
char *lob_get_index(lob_t p, uint32_t i)
{
  char *val;
  size_t len = 0;
  if(!p) return NULL;
  val = js0n(NULL,i,(char*)p->head,p->head_len,&len);
  return unescape(p,val,len);
}

// creates new packet from key:object
lob_t lob_get_json(lob_t p, char *key)
{
  lob_t pp;
  char *val;
  size_t len = 0;
  if(!p || !key) return NULL;

  val = js0n(key,0,(char*)p->head,p->head_len,&len);
  if(!val) return NULL;

  pp = lob_new();
  lob_head(pp, (uint8_t*)val, (uint16_t)len);
  return pp;
}

// list of packet->next from key:[{},{}]
lob_t lob_get_array(lob_t p, char *key)
{
  size_t i;
  char *val;
  size_t len = 0;
  lob_t parr, pent, plast = NULL, pret = NULL;
  if(!p || !key) return NULL;

  parr = lob_get_json(p, key);
  if(!parr || *parr->head != '[')
  {
    lob_free(parr);
    return NULL;
  }

  // parse each object in the array, link together
  for(i=0;(val = js0n(NULL,i,(char*)parr->head,parr->head_len,&len));i++)
  {
    pent = lob_new();
    lob_head(pent, (uint8_t*)val, (uint16_t)len);
    if(!pret) pret = pent;
    else plast->next = pent;
    plast = pent;
  }

  lob_free(parr);
  return pret;
}

// creates new packet w/ a body of the decoded base32 key value
lob_t lob_get_base32(lob_t p, char *key)
{
  lob_t ret;
  char *val;
  size_t len = 0;
  if(!p || !key) return NULL;

  val = js0n(key,0,(char*)p->head,p->head_len,&len);
  if(!val) return NULL;

  ret = lob_new();
  // make space to decode into the body
  if(!lob_body(ret,NULL,base32_decode_floor(len))) return lob_free(ret);
  // if the decoding wasn't successful, fail
  if(base32_decode(val,len,ret->body,ret->body_len) < ret->body_len) return lob_free(ret);
  return ret;
}

// just shorthand for util_cmp to match a key/value
int lob_get_cmp(lob_t p, char *key, char *val)
{
  return util_cmp(lob_get(p,key),val);
}


// count of keys
unsigned int lob_keys(lob_t p)
{
  size_t i, len = 0;
  if(!p) return 0;
  for(i=0;js0n(NULL,i,(char*)p->head,p->head_len,&len);i++);
  if(i % 2) return 0; // must be even number for key:val pairs
  return (unsigned int)i/2;
}

lob_t lob_sort(lob_t p)
{
  unsigned int i, len;
  char **keys;
  lob_t tmp;

  if(!p) return p;
  len = lob_keys(p);
  if(!len) return p;

  // create array of keys to sort
  keys = malloc(len*sizeof(char*));
  if(!keys) return LOG("OOM");
  for(i=0;i<len;i++)
  {
    keys[i] = lob_get_index(p,i*2);
  }

  // use default alpha sort
  util_sort(keys,len,sizeof(char*),NULL,NULL);

  // create the sorted json
  tmp = lob_new();
  for(i=0;i<len;i++)
  {
    lob_set_raw(tmp,keys[i],0,lob_get_raw(p,keys[i]),lob_get_len(p,keys[i]));
  }

  // replace json in original packet
  lob_head(p,tmp->head,tmp->head_len);
  lob_free(tmp);
  free(keys);
  return p;
}


int lob_cmp(lob_t a, lob_t b)
{
  unsigned int i = 0;
  char *str;
  if(!a || !b) return -1;
  if(a->body_len != b->body_len) return -1;
  if(lob_keys(a) != lob_keys(b)) return -1;

  lob_sort(a);
  lob_sort(b);
  while((str = lob_get_index(a,i)))
  {
    if(util_cmp(str,lob_get_index(b,i)) != 0) return -1;
    i++;
  }

  return util_ct_memcmp(a->body,b->body,a->body_len);
}

lob_t lob_set_json(lob_t p, lob_t json)
{
  char *key;
  uint32_t i = 0;

  while((key = lob_get_index(json,i)))
  {
    lob_set_raw(p,key,0,lob_get_raw(json,key),lob_get_len(json,key));
    i += 2;
  }
  return p;
}

// linked list utilities

lob_t lob_pop(lob_t list)
{
  lob_t end = list;
  if(!list) return NULL;
  while(end->next) end = end->next;
  end->next = lob_splice(list, end);
  return end;
}

lob_t lob_push(lob_t list, lob_t p)
{
  lob_t end;
  if(!p) return list;
  list = lob_splice(list, p);
  if(!list) return p;
  end = list;
  while(end->next) end = end->next;
  end->next = p;
  p->prev = end;
  p->next = NULL; // safety
  return list;
}

lob_t lob_shift(lob_t list)
{
  lob_t start = list;
  list = lob_splice(list, start);
  if(start) start->next = list;
  return start;
}

lob_t lob_unshift(lob_t list, lob_t p)
{
  if(!p) return list;
  list = lob_splice(list, p);
  if(!list) return p;
  p->next = list;
  list->prev = p;
  return p;
}

lob_t lob_splice(lob_t list, lob_t p)
{
  if(!p) return list;
  if(p->next) p->next->prev = p->prev;
  if(p->prev) p->prev->next = p->next;
  if(list == p) list = p->next;
  p->next = p->prev = NULL;
  return list;
}

lob_t lob_insert(lob_t list, lob_t after, lob_t p)
{
  if(!p) return list;
  list = lob_splice(list, p);
  if(!list) return p;
  if(!after) return LOG("bad args, need after");

  p->prev = after;
  p->next = after->next;
  if(after->next) after->next->prev = p;
  after->next = p;
  return list;
}

lob_t lob_freeall(lob_t list)
{
  if(!list) return NULL;
  lob_t next = list->next;
  list->next = NULL;
  lob_free(list);
  return lob_freeall(next);
}

// find the first packet in the list w/ the matching key/value
lob_t lob_match(lob_t list, char *key, char *value)
{
  if(!list || !key || !value) return NULL;
  if(lob_get_cmp(list,key,value) == 0) return list;
  return lob_match(list->next,key,value);
}

lob_t lob_next(lob_t list)
{
  if(!list) return NULL;
  return list->next;
}

// return json array of the list
lob_t lob_array(lob_t list)
{
  size_t len = 3; // []\0
  char *json;
  lob_t item, ret;

  if(!(json = malloc(len))) return LOG("OOM");
  sprintf(json,"[");
  for(item = list;item;item = lob_next(item))
  {
    len += item->head_len+1;
    if(!(json = util_reallocf(json, len))) return LOG("OOM");
    sprintf(json+strlen(json),"%.*s,",(int)item->head_len,item->head);
  }
  if(len == 3)
  {
    sprintf(json+strlen(json),"]");
  }else{
    sprintf(json+(strlen(json)-1),"]");
  }
  ret = lob_new();
  lob_head(ret,(uint8_t*)json, strlen(json));
  free(json);
  return ret;
}
#include "telehash.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "telehash.h"
#include "telehash.h"
#include "telehash.h" // for sha256 e3x_hash()

// how many csids can be used to make a hashname
#define MAX_CSIDS 8

// v* methods return this
static struct hashname_struct hn_vtmp;

hashname_t hashname_dup(hashname_t id)
{
  hashname_t hn;
  if(!(hn = malloc(sizeof (struct hashname_struct)))) return NULL;
  memset(hn,0,sizeof (struct hashname_struct));
  if(id) memcpy(hn->bin, id->bin, 32);
  return hn;
}

hashname_t hashname_free(hashname_t hn)
{
  if(hn == &hn_vtmp) return LOG("programmer error");
  if(hn) free(hn);
  return NULL;
}

// validate a str is a base32 hashname, returns TEMPORARY hashname
hashname_t hashname_vchar(const char *str)
{
  if(!str) return NULL;
  // decode will stop reading the first non-b32 char it sees, like a \0
  if(base32_decode(str,52,hn_vtmp.bin,32) != 32) return NULL;
  return &hn_vtmp;
}

hashname_t hashname_vbin(const uint8_t *bin)
{
  if(!bin) return NULL;
  memcpy(&hn_vtmp,bin,32);
  return &hn_vtmp;
}

// temp hashname from intermediate values as hex/base32 key/value pairs
hashname_t hashname_vkey(lob_t key, uint8_t csid)
{
  unsigned int i, start;
  uint8_t hash[64];
  char *id, *value, hexid[3];
  if(!key) return LOG("invalid args");
  util_hex(&csid, 1, hexid);
  memset(hash,0,64);

  // get in sorted order
  lob_sort(key);

  // loop through all keys rolling up
  uint8_t keys = 0;
  for(i=0;(id = lob_get_index(key,i));i+=2)
  {
    value = lob_get_index(key,i+1);
    if(strlen(id) != 2 || !util_ishex(id,2) || !value) continue; // skip non-id keys
    
    keys++;
    // hash the id
    util_unhex(id,2,hash+32);
    start = (i == 0) ? 32 : 0; // only first one excludes previous rollup
    e3x_hash(hash+start,(32-start)+1,hash); // hash in place

    // get the value from the body if matching csid arg
    if(util_cmp(id, hexid) == 0)
    {
      if(key->body_len == 0) return LOG("missing key body");
      // hash the body
      e3x_hash(key->body,key->body_len,hash+32);
    }else{
      if(strlen(value) != 52) return LOG("invalid value %s %d",value,strlen(value));
      if(base32_decode(value,52,hash+32,32) != 32) return LOG("base32 decode failed %s",value);
    }
    e3x_hash(hash,64,hash);
  }
  if(!keys) return LOG("no keys found in %s",lob_json(key));
  if(!i || i % 2 != 0) return LOG("invalid keys %d",i);
  
  return hashname_vbin(hash);
}

hashname_t hashname_vkeys(lob_t keys)
{
  hashname_t hn;
  lob_t im;

  if(!keys) return LOG("bad args");
  im = hashname_im(keys,0);
  hn = hashname_vkey(im,0);
  lob_free(im);
  return hn;
}

// accessors
uint8_t *hashname_bin(hashname_t hn)
{
  if(!hn) return NULL;
  return hn->bin;
}

// 52 byte base32 string w/ \0 (TEMPORARY)
static char hn_ctmp[53];
char *hashname_char(hashname_t hn)
{
  if(!hn) return NULL;
  base32_encode(hn->bin,32,hn_ctmp,53);
  return hn_ctmp;
}

int hashname_cmp(hashname_t a, hashname_t b)
{
  if(!a || !b) return -1;
  return memcmp(a->bin,b->bin,32);
}

uint8_t hashname_id(lob_t a, lob_t b)
{
  uint8_t id, best;
  uint32_t i;
  char *key;

  if(!a || !b) return 0;

  best = 0;
  for(i=0;(key = lob_get_index(a,i));i+=2)
  {
    if(strlen(key) != 2) continue;
    if(!lob_get(b,key)) continue;
    id = 0;
    util_unhex(key,2,&id);
    if(id > best) best = id;
  }
  
  return best;
}

// intermediate hashes in the json, if id is given it is attached as BODY instead
lob_t hashname_im(lob_t keys, uint8_t id)
{
  uint32_t i;
  size_t len;
  uint8_t *buf, hash[32];
  char *key, *value, hex[3];
  lob_t im;

  if(!keys) return LOG("bad args");

  // loop through all keys and create intermediates
  im = lob_new();
  buf = NULL;
  util_hex(&id,1,hex);
  for(i=0;(key = lob_get_index(keys,i));i+=2)
  {
    value = lob_get_index(keys,i+1);
    if(strlen(key) != 2 || !value) continue; // skip non-csid keys
    len = base32_decode_floor(strlen(value));
    // save to body raw or as a base32 intermediate value
    if(id && util_cmp(hex,key) == 0)
    {
      lob_body(im,NULL,len);
      if(base32_decode(value,strlen(value),im->body,len) != len) continue;
      lob_set_raw(im,key,0,"true",4);
    }else{
      buf = util_reallocf(buf,len);
      if(!buf) return lob_free(im);
      if(base32_decode(value,strlen(value),buf,len) != len) continue;
      // store the hash intermediate value
      e3x_hash(buf,len,hash);
      lob_set_base32(im,key,hash,32);
    }
  }
  if(buf) free(buf);
  return im;
}


// working with short hashnames (5 bin bytes, 8 char bytes)

// 8 byte base32 string w/ \0 (TEMPORARY)
char *hashname_short(hashname_t hn)
{
  static uint8_t tog = 1;
  if(!hn) return NULL;
  tog = tog ? 0 : 26; // fit two short names in hn_ctmp for easier LOG() args
  base32_encode(hn->bin,5,hn_ctmp+tog,53-tog);
  return hn_ctmp+tog;
}


// short only comparison
int hashname_scmp(hashname_t a, hashname_t b)
{
  if(!a || !b) return -1;
  return memcmp(a->bin,b->bin,5);
}


hashname_t hashname_schar(const char *str)
{
  if(!str) return NULL;
  memset(hn_vtmp.bin,0,32);
  if(base32_decode(str,8,hn_vtmp.bin,5) != 5) return NULL;
  return &hn_vtmp;
}

hashname_t hashname_sbin(const uint8_t *bin)
{
  if(!bin) return NULL;
  memset(hn_vtmp.bin,0,32);
  memcpy(hn_vtmp.bin,bin,5);
  return &hn_vtmp;
}

// NULL unless is short
hashname_t hashname_isshort(hashname_t hn)
{
  if(!hn) return NULL;
  uint8_t i;
  // check all 5-31 is zeros
  for(i=5;i<32;i++) if(hn->bin[i]) return NULL;
  return hn;
}

#include "telehash.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct xhashname_struct
{
    char flag;
    struct xhashname_struct *next;
    const char *key;
    void *val;
} *xhn;

struct xht_struct
{
    uint32_t prime;
    uint32_t iter;
    xhn zen;
};

/* Generates a hash code for a string.
 * This function uses the ELF hashing algorithm as reprinted in 
 * Andrew Binstock, "Hashing Rehashed," Dr. Dobb's Journal, April 1996.
 */
uint32_t _xhter(const char *s)
{
    /* ELF hash uses unsigned chars and unsigned arithmetic for portability */
    const unsigned char *name = (const unsigned char *)s;
    uint32_t h = 0, g;

    while (*name)
    {
       /* do some fancy bitwanking on the string */
        h = (h << 4) + (uint32_t)(*name++);
        if ((g = (h & 0xF0000000UL))!=0)
            h ^= (g >> 24);
        h &= ~g;
    }

    return h;
}


xhn _xht_node_find(xhn n, const char *key)
{
    for(;n != 0; n = n->next)
        if(n->key != 0 && strcmp(key, n->key) == 0)
            return n;
    return 0;
}


xht_t xht_new(unsigned int prime)
{
    xht_t xnew;

    xnew = (xht_t)malloc(sizeof(struct xht_struct));
    if(!xnew) return NULL;
    memset(xnew,0,sizeof(struct xht_struct));
    xnew->prime = (uint32_t)prime;
    xnew->zen = (xhn)malloc(sizeof(struct xhashname_struct)*prime); /* array of xhn size of prime */
    if(!xnew->zen)
    {
      free(xnew);
      return NULL;
    }
    memset(xnew->zen,0,sizeof(struct xhashname_struct)*prime);
    return xnew;
}

/* does the set work, used by xht_set and xht_store */
void _xht_set(xht_t h, const char *key, void *val, char flag)
{
    uint32_t i;
    xhn n;

    /* get our index for this key */
    i = _xhter(key) % h->prime;

    /* check for existing key first, or find an empty one */
    if((n = _xht_node_find(&h->zen[i], key)) == 0)
        for(n = &h->zen[i]; n != 0; n = n->next)
            if(n->val == 0)
                break;

    /* if none, make a new one, link into this index */
    if(n == 0)
    {
        n = (xhn)malloc(sizeof(struct xhashname_struct));
        if(!n) return;
        memset(n,0,sizeof(struct xhashname_struct));
        n->next = h->zen[i].next;
        h->zen[i].next = n;
    }

    /* when flag is set, we manage their mem and free em first */
    if(n->flag)
    {
        free((void*)n->key);
        free(n->val);
    }

    n->flag = flag;
    n->key = key;
    n->val = val;
}

void xht_set(xht_t h, const char *key, void *val)
{
    if(h == 0 || key == 0) return;
    _xht_set(h, key, val, 0);
}

void xht_store(xht_t h, const char *key, void *val, size_t vlen)
{
    char *ckey, *cval;
    size_t klen;

    if(h == 0 || key == 0 || (klen = strlen(key)) == 0) return;

    ckey = (char*)malloc(klen+1);
    if(!ckey) return;
    memcpy(ckey,key,klen);
    ckey[klen] = '\0';
    cval = (void*)malloc(vlen);
    if(!cval)
    {
      free(ckey);
      return;
    }
    memcpy(cval,val,vlen);
    _xht_set(h, ckey, cval, 1);
}


void *xht_get(xht_t h, const char *key)
{
    xhn n;

    if(h == 0 || key == 0) return 0;
    if((n = _xht_node_find(&h->zen[_xhter(key) % h->prime], key)) == 0) return 0;

    return n->val;
}


void xht_free(xht_t h)
{
    xhn n, f;
    uint32_t i;

    if(h == 0) return;

    for(i = 0; i < h->prime; i++)
        for(n = (&h->zen[i])->next; n != 0;)
        {
            f = n->next;
            if(n->flag)
            {
                free((void*)n->key);
                free(n->val);
            }
            free(n);
            n = f;
        }

    free(h->zen);
    free(h);
}

void xht_walk(xht_t h, xht_walker w, void *arg)
{
    uint32_t i;
    xhn n;

    if(h == 0 || w == 0)
        return;

    for(i = 0; i < h->prime; i++)
        for(n = &h->zen[i]; n != 0; n = n->next)
            if(n->key != 0 && n->val != 0)
                (*w)(h, n->key, n->val, arg);
}

char *xht_iter(xht_t h, char *key)
{
  xhn n;
  const char *ret;
  if(!h) return NULL;

  // reset/start
  if(!key) h->iter = 0;

  // step through each
  for(ret = NULL;!ret && h->iter < h->prime; h->iter++)
  {
    // find given key in current iter
    for(n = &h->zen[h->iter]; !ret && n; n = n->next)
    {
      // take the first one
      if(!key) ret = n->key;
      else if(n->key == key) key = NULL; // take the next one
      
    }
    if(ret) break;
    // return the next avail key
    key = NULL;
  }
  
  return (char*)ret;
}

// by jeremie miller - 2014
// public domain, contributions/improvements welcome via github at https://github.com/quartzjer/js0n

#include <string.h> // one strncmp() is used to do key comparison, and a strlen(key) if no len passed in

// gcc started warning for the init syntax used here, is not helpful so don't generate the spam, supressing the warning is really inconsistently supported across versions
#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Winitializer-overrides"
#pragma GCC diagnostic ignored "-Woverride-init"

#ifndef RODATA_SEGMENT_CONSTANT
#define RODATA_SEGMENT_CONSTANT
#endif

// only at depth 1, track start pointers to match key/value
#define PUSH(i) if(depth == 1) { if(!index) { val = cur+i; }else{ if(klen && index == 1) start = cur+i; else index--; } }

// determine if key matches or value is complete
#define CAP(i) if(depth == 1) { if(val && !index) {*vlen = (size_t)((cur+i+1) - val); return val;}; if(klen && start) {index = (klen == (size_t)(cur-start) && strncmp(key,start,klen)==0) ? 0 : 2; start = 0;} }

// this makes a single pass across the json bytes, using each byte as an index into a jump table to build an index and transition state
char *js0n(char *key, size_t klen, char *json, size_t jlen, size_t *vlen)
{
	char *val = 0;
	char *cur, *end, *start;
	size_t index = 1;
	int depth = 0;
	int utf8_remain = 0;
	static void *gostruct[] RODATA_SEGMENT_CONSTANT = 
	{
		[0 ... 255] = &&l_bad,
		['\t'] = &&l_loop, [' '] = &&l_loop, ['\r'] = &&l_loop, ['\n'] = &&l_loop,
		['"'] = &&l_qup,
		[':'] = &&l_loop,[','] = &&l_loop,
		['['] = &&l_up, [']'] = &&l_down, // tracking [] and {} individually would allow fuller validation but is really messy
		['{'] = &&l_up, ['}'] = &&l_down,
		['-'] = &&l_bare, [48 ... 57] = &&l_bare, // 0-9
		[65 ... 90] = &&l_bare, // A-Z
		[97 ... 122] = &&l_bare // a-z
	};
	static void *gobare[] RODATA_SEGMENT_CONSTANT = 
	{
		[0 ... 31] = &&l_bad,
		[32 ... 126] = &&l_loop, // could be more pedantic/validation-checking
		['\t'] = &&l_unbare, [' '] = &&l_unbare, ['\r'] = &&l_unbare, ['\n'] = &&l_unbare,
		[','] = &&l_unbare, [']'] = &&l_unbare, ['}'] = &&l_unbare, [':'] = &&l_unbare,
		[127 ... 255] = &&l_bad
	};
	static void *gostring[] RODATA_SEGMENT_CONSTANT = 
	{
		[0 ... 31] = &&l_bad, [127] = &&l_bad,
		[32 ... 126] = &&l_loop,
		['\\'] = &&l_esc, ['"'] = &&l_qdown,
		[128 ... 191] = &&l_bad,
		[192 ... 223] = &&l_utf8_2,
		[224 ... 239] = &&l_utf8_3,
		[240 ... 247] = &&l_utf8_4,
		[248 ... 255] = &&l_bad
	};
	static void *goutf8_continue[] RODATA_SEGMENT_CONSTANT =
	{
		[0 ... 127] = &&l_bad,
		[128 ... 191] = &&l_utf_continue,
		[192 ... 255] = &&l_bad
	};
	static void *goesc[] RODATA_SEGMENT_CONSTANT = 
	{
		[0 ... 255] = &&l_bad,
		['"'] = &&l_unesc, ['\\'] = &&l_unesc, ['/'] = &&l_unesc, ['b'] = &&l_unesc,
		['f'] = &&l_unesc, ['n'] = &&l_unesc, ['r'] = &&l_unesc, ['t'] = &&l_unesc, ['u'] = &&l_unesc
	};
	void **go = gostruct;
	
	if(!json || jlen <= 0 || !vlen) return 0;
	*vlen = 0;
	
	// no key is array mode, klen provides requested index
	if(!key)
	{
		index = klen;
		klen = 0;
	}else{
		if(klen <= 0) klen = strlen(key); // convenience
	}

	for(start=cur=json,end=cur+jlen; cur<end; cur++)
	{
			goto *go[(unsigned char)*cur];
			l_loop:;
	}
	
	if(depth) *vlen = jlen; // incomplete
	return 0;
	
	l_bad:
		*vlen = cur - json; // where error'd
		return 0;
	
	l_up:
		PUSH(0);
		++depth;
		goto l_loop;

	l_down:
		--depth;
		CAP(0);
		goto l_loop;

	l_qup:
		PUSH(1);
		go=gostring;
		goto l_loop;

	l_qdown:
		CAP(-1);
		go=gostruct;
		goto l_loop;
		
	l_esc:
		go = goesc;
		goto l_loop;
		
	l_unesc:
		go = gostring;
		goto l_loop;

	l_bare:
		PUSH(0);
		go = gobare;
		goto l_loop;

	l_unbare:
		CAP(-1);
		go = gostruct;
		goto *go[(unsigned char)*cur];

	l_utf8_2:
		go = goutf8_continue;
		utf8_remain = 1;
		goto l_loop;

	l_utf8_3:
		go = goutf8_continue;
		utf8_remain = 2;
		goto l_loop;

	l_utf8_4:
		go = goutf8_continue;
		utf8_remain = 3;
		goto l_loop;

	l_utf_continue:
		if (!--utf8_remain)
			go=gostring;
		goto l_loop;

}

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic pop
#endif
// Base32 implementation
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Modified 2015 Jeremie Miller
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string.h>

#include "telehash.h"

size_t base32_decode(const char *encoded, size_t length, uint8_t *result, size_t bufSize) {
  int buffer = 0;
  size_t bitsLeft = 0;
  size_t count = 0;
  const char *ptr = encoded;
  if(!encoded || !result  || bufSize <= 0) return 0;
  if(!length) length = strlen(encoded);
  for (; (size_t)(ptr-encoded) < length && count < bufSize; ++ptr) {
    uint8_t ch = (uint8_t)*ptr;
    if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-') {
      continue;
    }
    buffer <<= 5;

    // Deal with commonly mistyped characters
    if (ch == '0') {
      ch = 'O';
    } else if (ch == '1') {
      ch = 'L';
    } else if (ch == '8') {
      ch = 'B';
    }

    // Look up one base32 digit
    if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
      ch = (ch & 0x1F) - 1;
    } else if (ch >= '2' && ch <= '7') {
      ch -= '2' - 26;
    } else {
      return 0;
    }

    buffer |= ch;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      result[count++] = buffer >> (bitsLeft - 8);
      bitsLeft -= 8;
    }
  }
  if (count < bufSize) {
    result[count] = '\000';
  }
  return count;
}


size_t base32_encode(const uint8_t *data, size_t length, char *result, size_t bufSize) {
  if (!data || !result || !bufSize || !length) return 0;
  size_t count = 0;
  if (length > 0) {
    int buffer = data[0];
    size_t next = 1;
    int bitsLeft = 8;
    while (count < bufSize && (bitsLeft > 0 || next < length)) {
      if (bitsLeft < 5) {
        if (next < length) {
          buffer <<= 8;
          buffer |= data[next++] & 0xFF;
          bitsLeft += 8;
        } else {
          int pad = 5 - bitsLeft;
          buffer <<= pad;
          bitsLeft += pad;
        }
      }
      int index = 0x1F & (buffer >> (bitsLeft - 5));
      bitsLeft -= 5;
      result[count++] = "abcdefghijklmnopqrstuvwxyz234567"[index];
    }
  }
  if (count < bufSize) {
    result[count] = '\000';
  }
  return count;
}

size_t base32_encode_length(size_t rawLength)
{
  return ((rawLength * 8) / 5) + ((rawLength % 5) != 0) + 1;
}

size_t base32_decode_floor(size_t base32Length)
{
  return ((base32Length * 5) / 8);
}

#include "telehash.h"

/*
 chacha-merged.c version 20080118
 D. J. Bernstein
 Public domain.
 */

#include <sys/types.h>
#include <stddef.h>

struct chacha_ctx {
	unsigned input[16];
};

#define CHACHA_MINKEYLEN 	16
#define CHACHA_NONCELEN		8
#define CHACHA_CTRLEN		8
#define CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

// old gcc
#if !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__) 
#define __bounded__(x, y, z) __unused__ 
#endif

void chacha_keysetup(struct chacha_ctx *x, const u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
void chacha_ivsetup(struct chacha_ctx *x, const u_char *iv, const u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
void chacha_encrypt_bytes(struct chacha_ctx *x, const u_char *m,
    u_char *c, u_int bytes)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

/* $OpenBSD: chacha.c,v 1.1 2013/11/21 00:45:44 djm Exp $ */

typedef unsigned char u8;
typedef unsigned int u32;

typedef struct chacha_ctx chacha_ctx;

#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((u8)(v) & U8C(0xFF))
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void chacha_keysetup (chacha_ctx *x, const u8 *k, u32 kbits)
{
	const char *constants;

	x->input[4] = U8TO32_LITTLE(k + 0);
	x->input[5] = U8TO32_LITTLE(k + 4);
	x->input[6] = U8TO32_LITTLE(k + 8);
	x->input[7] = U8TO32_LITTLE(k + 12);
	if (kbits == 256) { /* recommended */
		k += 16;
		constants = sigma;
	}
	else { /* kbits == 128 */
		constants = tau;
	}
	x->input[8] = U8TO32_LITTLE(k + 0);
	x->input[9] = U8TO32_LITTLE(k + 4);
	x->input[10] = U8TO32_LITTLE(k + 8);
	x->input[11] = U8TO32_LITTLE(k + 12);
	x->input[0] = U8TO32_LITTLE(constants + 0);
	x->input[1] = U8TO32_LITTLE(constants + 4);
	x->input[2] = U8TO32_LITTLE(constants + 8);
	x->input[3] = U8TO32_LITTLE(constants + 12);
}

void chacha_ivsetup (chacha_ctx *x, const u8 *iv, const u8 *counter)
{
	x->input[12] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 0);
	x->input[13] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 4);
	x->input[14] = U8TO32_LITTLE(iv + 0);
	x->input[15] = U8TO32_LITTLE(iv + 4);
}

void chacha_encrypt_bytes (chacha_ctx *x, const u8 *m, u8 *c, u32 bytes)
{
	u32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
	u32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
	u8 *ctarget = NULL;
	u8 tmp[64];
	u_int i;

	if (!bytes)
		return;

	j0 = x->input[0];
	j1 = x->input[1];
	j2 = x->input[2];
	j3 = x->input[3];
	j4 = x->input[4];
	j5 = x->input[5];
	j6 = x->input[6];
	j7 = x->input[7];
	j8 = x->input[8];
	j9 = x->input[9];
	j10 = x->input[10];
	j11 = x->input[11];
	j12 = x->input[12];
	j13 = x->input[13];
	j14 = x->input[14];
	j15 = x->input[15];

	for (;;) {
		if (bytes < 64) {
			for (i = 0; i < bytes; ++i)
				tmp[i] = m[i];
			m = tmp;
			ctarget = c;
			c = tmp;
		}
		x0 = j0;
		x1 = j1;
		x2 = j2;
		x3 = j3;
		x4 = j4;
		x5 = j5;
		x6 = j6;
		x7 = j7;
		x8 = j8;
		x9 = j9;
		x10 = j10;
		x11 = j11;
		x12 = j12;
		x13 = j13;
		x14 = j14;
		x15 = j15;
		for (i = 20; i > 0; i -= 2) {
			QUARTERROUND(x0, x4, x8, x12)
			QUARTERROUND(x1, x5, x9, x13)
			QUARTERROUND(x2, x6, x10, x14)
			QUARTERROUND(x3, x7, x11, x15)
			QUARTERROUND(x0, x5, x10, x15)
			QUARTERROUND(x1, x6, x11, x12)
			QUARTERROUND(x2, x7, x8, x13)
			QUARTERROUND(x3, x4, x9, x14)
		}
		x0 = PLUS(x0, j0);
		x1 = PLUS(x1, j1);
		x2 = PLUS(x2, j2);
		x3 = PLUS(x3, j3);
		x4 = PLUS(x4, j4);
		x5 = PLUS(x5, j5);
		x6 = PLUS(x6, j6);
		x7 = PLUS(x7, j7);
		x8 = PLUS(x8, j8);
		x9 = PLUS(x9, j9);
		x10 = PLUS(x10, j10);
		x11 = PLUS(x11, j11);
		x12 = PLUS(x12, j12);
		x13 = PLUS(x13, j13);
		x14 = PLUS(x14, j14);
		x15 = PLUS(x15, j15);

		x0 = XOR(x0, U8TO32_LITTLE(m + 0));
		x1 = XOR(x1, U8TO32_LITTLE(m + 4));
		x2 = XOR(x2, U8TO32_LITTLE(m + 8));
		x3 = XOR(x3, U8TO32_LITTLE(m + 12));
		x4 = XOR(x4, U8TO32_LITTLE(m + 16));
		x5 = XOR(x5, U8TO32_LITTLE(m + 20));
		x6 = XOR(x6, U8TO32_LITTLE(m + 24));
		x7 = XOR(x7, U8TO32_LITTLE(m + 28));
		x8 = XOR(x8, U8TO32_LITTLE(m + 32));
		x9 = XOR(x9, U8TO32_LITTLE(m + 36));
		x10 = XOR(x10, U8TO32_LITTLE(m + 40));
		x11 = XOR(x11, U8TO32_LITTLE(m + 44));
		x12 = XOR(x12, U8TO32_LITTLE(m + 48));
		x13 = XOR(x13, U8TO32_LITTLE(m + 52));
		x14 = XOR(x14, U8TO32_LITTLE(m + 56));
		x15 = XOR(x15, U8TO32_LITTLE(m + 60));

		j12 = PLUSONE(j12);
		if (!j12) {
			j13 = PLUSONE(j13);
			/* stopping at 2^70 bytes per nonce is user's responsibility */
		}

		U32TO8_LITTLE(c + 0, x0);
		U32TO8_LITTLE(c + 4, x1);
		U32TO8_LITTLE(c + 8, x2);
		U32TO8_LITTLE(c + 12, x3);
		U32TO8_LITTLE(c + 16, x4);
		U32TO8_LITTLE(c + 20, x5);
		U32TO8_LITTLE(c + 24, x6);
		U32TO8_LITTLE(c + 28, x7);
		U32TO8_LITTLE(c + 32, x8);
		U32TO8_LITTLE(c + 36, x9);
		U32TO8_LITTLE(c + 40, x10);
		U32TO8_LITTLE(c + 44, x11);
		U32TO8_LITTLE(c + 48, x12);
		U32TO8_LITTLE(c + 52, x13);
		U32TO8_LITTLE(c + 56, x14);
		U32TO8_LITTLE(c + 60, x15);

		if (bytes <= 64) {
			if (bytes < 64) {
				for (i = 0; i < bytes; ++i)
					ctarget[i] = c[i];
			}
			x->input[12] = j12;
			x->input[13] = j13;
			return;
		}
		bytes -= 64;
		c += 64;
		m += 64;
	}
}


uint8_t *chacha20(uint8_t *key, uint8_t *nonce, uint8_t *bytes, uint32_t len)
{
  struct chacha_ctx ctx;
  if(!len) return bytes;

  chacha_keysetup (&ctx, key, 32 * 8);
  chacha_ivsetup (&ctx, nonce, NULL);

  chacha_encrypt_bytes (&ctx, bytes, bytes, len);
  return bytes;
}

#undef ROTL32
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "telehash.h"

// local wrappers
uint32_t murmur4(const uint8_t *data, uint32_t len)
{
  return PMurHash32(0, data, len);
}

char *murmur8(const uint8_t *data, uint32_t len, char *hex)
{
  uint32_t hash = murmur4(data,len);
  sprintf(hex,"%08lx",(unsigned long)hash);
  return hex;
}

uint8_t *murmur(const uint8_t *data, uint32_t len, uint8_t *hash)
{
  uint32_t num = murmur4(data,len);
  memcpy(hash,&num,4);
  return hash;
}

/*-----------------------------------------------------------------------------
 * MurmurHash3 was written by Austin Appleby, and is placed in the public
 * domain.
 *
 * This implementation was written by Shane Day, and is also public domain.
 *
 * This is a portable ANSI C implementation of MurmurHash3_x86_32 (Murmur3A)
 * with support for progressive processing.
 */

/*-----------------------------------------------------------------------------
 
If you want to understand the MurmurHash algorithm you would be much better
off reading the original source. Just point your browser at:
http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp


What this version provides?

1. Progressive data feeding. Useful when the entire payload to be hashed
does not fit in memory or when the data is streamed through the application.
Also useful when hashing a number of strings with a common prefix. A partial
hash of a prefix string can be generated and reused for each suffix string.

2. Portability. Plain old C so that it should compile on any old compiler.
Both CPU endian and access-alignment neutral, but avoiding inefficient code
when possible depending on CPU capabilities.

3. Drop in. I personally like nice self contained public domain code, making it
easy to pilfer without loads of refactoring to work properly in the existing
application code & makefile structure and mucking around with licence files.
Just copy PMurHash.h and PMurHash.c and you're ready to go.


How does it work?

We can only process entire 32 bit chunks of input, except for the very end
that may be shorter. So along with the partial hash we need to give back to
the caller a carry containing up to 3 bytes that we were unable to process.
This carry also needs to record the number of bytes the carry holds. I use
the low 2 bits as a count (0..3) and the carry bytes are shifted into the
high byte in stream order.

To handle endianess I simply use a macro that reads a uint32_t and define
that macro to be a direct read on little endian machines, a read and swap
on big endian machines, or a byte-by-byte read if the endianess is unknown.

-----------------------------------------------------------------------------*/


/* MSVC warnings we choose to ignore */
#if defined(_MSC_VER)
  #pragma warning(disable: 4127) /* conditional expression is constant */
#endif

/*-----------------------------------------------------------------------------
 * Endianess, misalignment capabilities and util macros
 *
 * The following 3 macros are defined in this section. The other macros defined
 * are only needed to help derive these 3.
 *
 * READ_UINT32(x)   Read a little endian unsigned 32-bit int
 * UNALIGNED_SAFE   Defined if READ_UINT32 works on non-word boundaries
 * ROTL32(x,r)      Rotate x left by r bits
 */

/* Convention is to define __BYTE_ORDER == to one of these values */
#if !defined(__BIG_ENDIAN)
  #define __BIG_ENDIAN 4321
#endif
#if !defined(__LITTLE_ENDIAN)
  #define __LITTLE_ENDIAN 1234
#endif

/* I386 */
#if defined(_M_IX86) || defined(__i386__) || defined(__i386) || defined(i386)
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #define UNALIGNED_SAFE
#endif

/* gcc 'may' define __LITTLE_ENDIAN__ or __BIG_ENDIAN__ to 1 (Note the trailing __),
 * or even _LITTLE_ENDIAN or _BIG_ENDIAN (Note the single _ prefix) */
#if !defined(__BYTE_ORDER)
  #if defined(__LITTLE_ENDIAN__) && __LITTLE_ENDIAN__==1 || defined(_LITTLE_ENDIAN) && _LITTLE_ENDIAN==1
    #define __BYTE_ORDER __LITTLE_ENDIAN
  #elif defined(__BIG_ENDIAN__) && __BIG_ENDIAN__==1 || defined(_BIG_ENDIAN) && _BIG_ENDIAN==1
    #define __BYTE_ORDER __BIG_ENDIAN
  #endif
#endif

/* gcc (usually) defines xEL/EB macros for ARM and MIPS endianess */
#if !defined(__BYTE_ORDER)
  #if defined(__ARMEL__) || defined(__MIPSEL__)
    #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #if defined(__ARMEB__) || defined(__MIPSEB__)
    #define __BYTE_ORDER __BIG_ENDIAN
  #endif
#endif

/* Now find best way we can to READ_UINT32 */
#if __BYTE_ORDER==__LITTLE_ENDIAN
  /* CPU endian matches murmurhash algorithm, so read 32-bit word directly */
  #define READ_UINT32(ptr)   (*((uint32_t*)(ptr)))
#elif __BYTE_ORDER==__BIG_ENDIAN
  /* TODO: Add additional cases below where a compiler provided bswap32 is available */
  #if defined(__GNUC__) && (__GNUC__>4 || (__GNUC__==4 && __GNUC_MINOR__>=3))
    #define READ_UINT32(ptr)   (__builtin_bswap32(*((uint32_t*)(ptr))))
  #else
    /* Without a known fast bswap32 we're just as well off doing this */
    #define READ_UINT32(ptr)   (ptr[0]|ptr[1]<<8|ptr[2]<<16|ptr[3]<<24)
    #define UNALIGNED_SAFE
  #endif
#else
  /* Unknown endianess so last resort is to read individual bytes */
  #define READ_UINT32(ptr)   (ptr[0]|ptr[1]<<8|ptr[2]<<16|ptr[3]<<24)

  /* Since we're not doing word-reads we can skip the messing about with realignment */
  #define UNALIGNED_SAFE
#endif

/* Find best way to ROTL32 */
#if defined(_MSC_VER)
  #include <stdlib.h>  /* Microsoft put _rotl declaration in here */
  #define ROTL32(x,r)  _rotl(x,r)
#else
  /* gcc recognises this code and generates a rotate instruction for CPUs with one */
  #define ROTL32(x,r)  (((uint32_t)x << r) | ((uint32_t)x >> (32 - r)))
#endif


/*-----------------------------------------------------------------------------
 * Core murmurhash algorithm macros */

#define C1  (0xcc9e2d51)
#define C2  (0x1b873593)

/* This is the main processing body of the algorithm. It operates
 * on each full 32-bits of input. */
#define DOBLOCK(h1, k1) do{ \
        k1 *= C1; \
        k1 = ROTL32(k1,15); \
        k1 *= C2; \
        \
        h1 ^= k1; \
        h1 = ROTL32(h1,13); \
        h1 = h1*5+0xe6546b64; \
    }while(0)


/* Append unaligned bytes to carry, forcing hash churn if we have 4 bytes */
/* cnt=bytes to process, h1=name of h1 var, c=carry, n=bytes in c, ptr/len=payload */
#define DOBYTES(cnt, h1, c, n, ptr, len) do{ \
    int _i = cnt; \
    while(_i--) { \
        c = c>>8 | *ptr++<<24; \
        n++; len--; \
        if(n==4) { \
            DOBLOCK(h1, c); \
            n = 0; \
        } \
    } }while(0)

/*---------------------------------------------------------------------------*/

/* Main hashing function. Initialise carry to 0 and h1 to 0 or an initial seed
 * if wanted. Both ph1 and pcarry are required arguments. */
void PMurHash32_Process(uint32_t *ph1, uint32_t *pcarry, const void *key, int len)
{
  uint32_t h1 = *ph1;
  uint32_t c = *pcarry;

  const uint8_t *ptr = (uint8_t*)key;
  const uint8_t *end;

  /* Extract carry count from low 2 bits of c value */
  int n = c & 3;

#if defined(UNALIGNED_SAFE)
  /* This CPU handles unaligned word access */

  /* Consume any carry bytes */
  int i = (4-n) & 3;
  if(i && i <= len) {
    DOBYTES(i, h1, c, n, ptr, len);
  }

  /* Process 32-bit chunks */
  end = ptr + len/4*4;
  for( ; ptr < end ; ptr+=4) {
    uint32_t k1 = READ_UINT32(ptr);
    DOBLOCK(h1, k1);
  }

#else /*UNALIGNED_SAFE*/
  /* This CPU does not handle unaligned word access */

  /* Consume enough so that the next data byte is word aligned */
  int i = -(long)ptr & 3;
  if(i && i <= len) {
      DOBYTES(i, h1, c, n, ptr, len);
  }

  /* We're now aligned. Process in aligned blocks. Specialise for each possible carry count */
  end = ptr + len/4*4;
  switch(n) { /* how many bytes in c */
  case 0: /* c=[----]  w=[3210]  b=[3210]=w            c'=[----] */
    for( ; ptr < end ; ptr+=4) {
      uint32_t k1 = READ_UINT32(ptr);
      DOBLOCK(h1, k1);
    }
    break;
  case 1: /* c=[0---]  w=[4321]  b=[3210]=c>>24|w<<8   c'=[4---] */
    for( ; ptr < end ; ptr+=4) {
      uint32_t k1 = c>>24;
      c = READ_UINT32(ptr);
      k1 |= c<<8;
      DOBLOCK(h1, k1);
    }
    break;
  case 2: /* c=[10--]  w=[5432]  b=[3210]=c>>16|w<<16  c'=[54--] */
    for( ; ptr < end ; ptr+=4) {
      uint32_t k1 = c>>16;
      c = READ_UINT32(ptr);
      k1 |= c<<16;
      DOBLOCK(h1, k1);
    }
    break;
  case 3: /* c=[210-]  w=[6543]  b=[3210]=c>>8|w<<24   c'=[654-] */
    for( ; ptr < end ; ptr+=4) {
      uint32_t k1 = c>>8;
      c = READ_UINT32(ptr);
      k1 |= c<<24;
      DOBLOCK(h1, k1);
    }
  }
#endif /*UNALIGNED_SAFE*/

  /* Advance over whole 32-bit chunks, possibly leaving 1..3 bytes */
  len -= len/4*4;

  /* Append any remaining bytes into carry */
  DOBYTES(len, h1, c, n, ptr, len);

  /* Copy out new running hash and carry */
  *ph1 = h1;
  *pcarry = (c & ~0xff) | n;
} 

/*---------------------------------------------------------------------------*/

/* Finalize a hash. To match the original Murmur3A the total_length must be provided */
uint32_t PMurHash32_Result(uint32_t h, uint32_t carry, uint32_t total_length)
{
  uint32_t k1;
  int n = carry & 3;
  if(n) {
    k1 = carry >> (4-n)*8;
    k1 *= C1; k1 = ROTL32(k1,15); k1 *= C2; h ^= k1;
  }
  h ^= total_length;

  /* fmix */
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;

  return h;
}

/*---------------------------------------------------------------------------*/

/* Murmur3A compatable all-at-once */
uint32_t PMurHash32(uint32_t seed, const void *key, int len)
{
  uint32_t h1=seed, carry=0;
  PMurHash32_Process(&h1, &carry, key, len);
  return PMurHash32_Result(h1, carry, len);
}

/*---------------------------------------------------------------------------*/

/* Provide an API suitable for smhasher */
void PMurHash32_test(const void *key, int len, uint32_t seed, void *out)
{
  uint32_t h1=seed, carry=0;
  const uint8_t *ptr = (uint8_t*)key;
  const uint8_t *end = ptr + len;

#if 0 /* Exercise the progressive processing */
  while(ptr < end) {
    //const uint8_t *mid = ptr + rand()%(end-ptr)+1;
    const uint8_t *mid = ptr + (rand()&0xF);
    mid = mid<end?mid:end;
    PMurHash32_Process(&h1, &carry, ptr, mid-ptr);
    ptr = mid;
  }
#else
  PMurHash32_Process(&h1, &carry, ptr, (int)(end-ptr));
#endif
  h1 = PMurHash32_Result(h1, carry, len);
  *(uint32_t*)out = h1;
}

/*---------------------------------------------------------------------------*/

#undef ROTL32
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "telehash.h"

// this lib implements basic JWT support using the crypto/lob utilities in telehash-c

// one JWT is two chained packets using lob.c
//  token->head is the JWT header JSON
//  token->body is a raw LOB for the claims
//  claims->head is the JWT claims JSON
//  claims->body is the JWT signature

// decode base64 into the pair of lob packets
lob_t jwt_decode(char *encoded, size_t len)
{
  lob_t header, claims;
  char *dot1, *dot2, *end;

  if(!encoded) return NULL;
  if(!len) len = strlen(encoded);
  end = encoded+(len-1);
  
  // make sure the dot separators are there
  dot1 = strchr(encoded,'.');
  if(!dot1 || dot1+1 >= end) return LOG_INFO("missing/bad first separator");
  dot1++;
  dot2 = strchr(dot1,'.');
  if(!dot2 || (dot2+1) >= end) return LOG_INFO("missing/bad second separator");
  dot2++;

  // quick sanity check of the base64
  if(!base64_decoder(dot2, (end-dot2)+1, NULL)) return LOG_INFO("invalid sig base64: %.*s",(end-dot2)+1,dot2);
  if(!base64_decoder(dot1, (dot2-dot1)-1, NULL)) return LOG_INFO("invalid claims base64: %.*s",(dot2-dot1)-1,dot1);
  if(!base64_decoder(encoded, (dot1-encoded)-1, NULL)) return LOG_INFO("invalid header b64: %.*s",(dot1-encoded)-1,encoded);

  claims = lob_new();
  header = lob_link(NULL, claims);
  
  // decode claims json
  lob_head(claims, NULL, base64_decoder(dot1, (dot2-dot1)-1, NULL));
  base64_decoder(dot1, (dot2-dot1)-1, lob_head_get(claims));

  // decode claims sig 
  lob_body(claims, NULL, base64_decoder(dot2, (end-dot2)+1, NULL));
  base64_decoder(dot2, (end-dot2)+1, lob_body_get(claims));

  // decode header json
  lob_head(header, NULL, base64_decoder(encoded, (dot1-encoded)-1, NULL));
  base64_decoder(encoded, (dot1-encoded)-1, lob_head_get(header));

  return header;
}

// util to parse token from binary lob-encoding
lob_t jwt_parse(uint8_t *raw, size_t len)
{
  return NULL;
}

// just returns the token->chain claims claim
lob_t jwt_claims(lob_t token)
{
  return lob_linked(token);
}

// returns the base64 encoded token from a packet
char *jwt_encode(lob_t token)
{
  lob_t claims = jwt_claims(token);
  if(!claims) return LOG_WARN("no claims");
  
  size_t slen = base64_encode_length(claims->body_len);
  size_t clen = base64_encode_length(claims->head_len);
  size_t hlen = base64_encode_length(token->head_len);
  char *encoded;
  if(!(encoded = malloc(hlen+1+clen+1+slen+1))) return LOG_WARN("OOM");
  
  // append all the base64 encoding
  hlen = base64_encoder(token->head,token->head_len,encoded);
  encoded[hlen] = '.';
  clen = base64_encoder(claims->head,claims->head_len,encoded+hlen+1);
  encoded[hlen+1+clen] = '.';
  slen = base64_encoder(claims->body,claims->body_len,encoded+hlen+1+clen+1);
  encoded[hlen+1+clen+1+slen] = 0;

  return encoded;
}

// lob-encoded raw bytes of a token
uint8_t *jwt_raw(lob_t token)
{
  return LOG_INFO("TODO");
}

// length of raw bytes
uint32_t jwt_len(lob_t token)
{
  return 0;
}

// verify the signature on this token, optionally using key loaded in this exchange
lob_t jwt_verify(lob_t token, e3x_exchange_t x)
{
  lob_t claims = jwt_claims(token);
  if(!token || !claims) return LOG("bad args");

  // generate the temporary encoded data
  char *encoded = jwt_encode(token);
  if(!encoded) return LOG("bad token");
  char *dot = strchr(encoded,'.');
  dot = strchr(dot+1,'.');
  
  LOG("checking %lu %.*s",lob_body_len(token),dot-encoded,encoded);

  // do the validation against the sig on the claims using info from the token
  uint8_t err = e3x_exchange_validate(x, token, claims, (uint8_t*)encoded, dot-encoded);
  free(encoded);

  if(err) return LOG("validate failed: %d",err);
  return token;
}

// sign this token, adds signature to the claims body
lob_t jwt_sign(lob_t token, e3x_self_t self)
{
  lob_t claims = jwt_claims(token);
  if(!token || !claims) return LOG("bad args");

  // generate the temporary encoded data
  char *encoded = jwt_encode(token);
  if(!encoded) return LOG("bad token");
  char *dot = strchr(encoded,'.');
  dot = strchr(dot+1,'.');

  // e3x returns token w/ signature as the body
  if(!e3x_self_sign(self, token, (uint8_t*)encoded, dot-encoded)) return LOG("signing failed");
  free(encoded);
  
  // move sig to claims
  lob_body(claims,token->body,token->body_len);
  lob_body(token,NULL,0);

  return token;
}

// if this alg is supported
char *jwt_alg(char *alg)
{
  if(!alg) return LOG("missing arg");
  return (e3x_cipher_set(0,alg)) ? alg : NULL;
}
/* some very basic public-domain base64 functions */
#include "telehash.h"
#include <stdint.h>
#include <string.h>

// decode str of len into out (must be base64_decode_length(len) bit), return actual decoded len
size_t base64_decoder(const char *str, size_t len, uint8_t *save)
{
    const char *cur;
    uint8_t *start;
    int8_t d;
    uint8_t c, phase, dlast;
    static int8_t table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63,  /* 20-2F */
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,  /* 50-5F */
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
    };

    if(!str) return 0;
    if(!len) len = strlen(str);
    
    // allow null save to just return exact size
    uint8_t *out = save;
    if(!out) out = (uint8_t*)str;

    d = dlast = phase = 0;
    start = out;
    for (cur = str; *cur != '\0' && len; ++cur, --len)
    {
        /* handle newlines as seperate chunks */
        if(*cur == '\n' || *cur == '\r')
        {
            phase = dlast = 0;
            continue;
        }

        d = table[(int)*cur];
        if(d >= 0)
        {
            switch(phase)
            {
            case 0:
                ++phase;
                break;
            case 1:
                c = ((dlast << 2) | ((d & 0x30) >> 4));
                if(save) *out = c;
                ++out;
                ++phase;
                break;
            case 2:
                c = (((dlast & 0xf) << 4) | ((d & 0x3c) >> 2));
                if(save) *out = c;
                ++out;
                ++phase;
                break;
            case 3:
                c = (((dlast & 0x03 ) << 6) | d);
                if(save) *out = c;
                ++out;
                phase = 0;
                break;
            }
            dlast = d;
        }else{
          return 0;
        }
    }
    return out - start;
}



// encode str of len into out (must be at least base64_encode_length(len) big), return encoded len
size_t base64_encoder(const uint8_t *str, size_t len, char *out)
{
    size_t i;
    uint8_t s1, s2;
    char *cur = out;
    static uint8_t table[64] = {
        'A','B','C','D','E','F','G','H',
        'I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X',
        'Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n',
        'o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3',
        '4','5','6','7','8','9','-','_'
    };

    if(!str || !out || !len) return 0;

    for (i = 0; i < len; i += 3, str += 3)
    {
      s1 = (i+1<len)?str[1]:0;
      s2 = (i+2<len)?str[2]:0;
      *cur++ = table[str[0] >> 2];
      *cur++ = table[((str[0] & 3) << 4) + (s1 >> 4)];
      *cur++ = table[((s1 & 0xf) << 2) + (s2 >> 6)];
      *cur++ = table[s2 & 0x3f];
    }

    if (i == len + 1)
        *(cur - 1) = '=';
    else if (i == len + 2)
        *(cur - 1) = *(cur - 2) = '=';
    *cur = '\0';

    // return actual length, not padded
    return (cur - out) - (i-len);
}
/*
 *  FIPS-197 compliant AES implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
 *
 *  http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */


#include <string.h>
#include "aes128.h"

void aes_128_ctr(unsigned char *key, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output)
{
  mbedtls_aes_context ctx;
  size_t off = 0;
  unsigned char block[16];

  mbedtls_aes_setkey_enc(&ctx,key,128);
  mbedtls_aes_crypt_ctr(&ctx,length,&off,iv,block,input,output);
}

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                                    \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
}
#endif

#if defined(MBEDTLS_PADLOCK_C) &&                      \
    ( defined(MBEDTLS_HAVE_X86) || defined(MBEDTLS_PADLOCK_ALIGN16) )
static int aes_padlock_ace = -1;
#endif

#if defined(MBEDTLS_AES_ROM_TABLES)
/*
 * Forward S-box
 */
static const unsigned char FSb[256] =
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/*
 * Forward tables
 */
#define FT \
\
    V(A5,63,63,C6), V(84,7C,7C,F8), V(99,77,77,EE), V(8D,7B,7B,F6), \
    V(0D,F2,F2,FF), V(BD,6B,6B,D6), V(B1,6F,6F,DE), V(54,C5,C5,91), \
    V(50,30,30,60), V(03,01,01,02), V(A9,67,67,CE), V(7D,2B,2B,56), \
    V(19,FE,FE,E7), V(62,D7,D7,B5), V(E6,AB,AB,4D), V(9A,76,76,EC), \
    V(45,CA,CA,8F), V(9D,82,82,1F), V(40,C9,C9,89), V(87,7D,7D,FA), \
    V(15,FA,FA,EF), V(EB,59,59,B2), V(C9,47,47,8E), V(0B,F0,F0,FB), \
    V(EC,AD,AD,41), V(67,D4,D4,B3), V(FD,A2,A2,5F), V(EA,AF,AF,45), \
    V(BF,9C,9C,23), V(F7,A4,A4,53), V(96,72,72,E4), V(5B,C0,C0,9B), \
    V(C2,B7,B7,75), V(1C,FD,FD,E1), V(AE,93,93,3D), V(6A,26,26,4C), \
    V(5A,36,36,6C), V(41,3F,3F,7E), V(02,F7,F7,F5), V(4F,CC,CC,83), \
    V(5C,34,34,68), V(F4,A5,A5,51), V(34,E5,E5,D1), V(08,F1,F1,F9), \
    V(93,71,71,E2), V(73,D8,D8,AB), V(53,31,31,62), V(3F,15,15,2A), \
    V(0C,04,04,08), V(52,C7,C7,95), V(65,23,23,46), V(5E,C3,C3,9D), \
    V(28,18,18,30), V(A1,96,96,37), V(0F,05,05,0A), V(B5,9A,9A,2F), \
    V(09,07,07,0E), V(36,12,12,24), V(9B,80,80,1B), V(3D,E2,E2,DF), \
    V(26,EB,EB,CD), V(69,27,27,4E), V(CD,B2,B2,7F), V(9F,75,75,EA), \
    V(1B,09,09,12), V(9E,83,83,1D), V(74,2C,2C,58), V(2E,1A,1A,34), \
    V(2D,1B,1B,36), V(B2,6E,6E,DC), V(EE,5A,5A,B4), V(FB,A0,A0,5B), \
    V(F6,52,52,A4), V(4D,3B,3B,76), V(61,D6,D6,B7), V(CE,B3,B3,7D), \
    V(7B,29,29,52), V(3E,E3,E3,DD), V(71,2F,2F,5E), V(97,84,84,13), \
    V(F5,53,53,A6), V(68,D1,D1,B9), V(00,00,00,00), V(2C,ED,ED,C1), \
    V(60,20,20,40), V(1F,FC,FC,E3), V(C8,B1,B1,79), V(ED,5B,5B,B6), \
    V(BE,6A,6A,D4), V(46,CB,CB,8D), V(D9,BE,BE,67), V(4B,39,39,72), \
    V(DE,4A,4A,94), V(D4,4C,4C,98), V(E8,58,58,B0), V(4A,CF,CF,85), \
    V(6B,D0,D0,BB), V(2A,EF,EF,C5), V(E5,AA,AA,4F), V(16,FB,FB,ED), \
    V(C5,43,43,86), V(D7,4D,4D,9A), V(55,33,33,66), V(94,85,85,11), \
    V(CF,45,45,8A), V(10,F9,F9,E9), V(06,02,02,04), V(81,7F,7F,FE), \
    V(F0,50,50,A0), V(44,3C,3C,78), V(BA,9F,9F,25), V(E3,A8,A8,4B), \
    V(F3,51,51,A2), V(FE,A3,A3,5D), V(C0,40,40,80), V(8A,8F,8F,05), \
    V(AD,92,92,3F), V(BC,9D,9D,21), V(48,38,38,70), V(04,F5,F5,F1), \
    V(DF,BC,BC,63), V(C1,B6,B6,77), V(75,DA,DA,AF), V(63,21,21,42), \
    V(30,10,10,20), V(1A,FF,FF,E5), V(0E,F3,F3,FD), V(6D,D2,D2,BF), \
    V(4C,CD,CD,81), V(14,0C,0C,18), V(35,13,13,26), V(2F,EC,EC,C3), \
    V(E1,5F,5F,BE), V(A2,97,97,35), V(CC,44,44,88), V(39,17,17,2E), \
    V(57,C4,C4,93), V(F2,A7,A7,55), V(82,7E,7E,FC), V(47,3D,3D,7A), \
    V(AC,64,64,C8), V(E7,5D,5D,BA), V(2B,19,19,32), V(95,73,73,E6), \
    V(A0,60,60,C0), V(98,81,81,19), V(D1,4F,4F,9E), V(7F,DC,DC,A3), \
    V(66,22,22,44), V(7E,2A,2A,54), V(AB,90,90,3B), V(83,88,88,0B), \
    V(CA,46,46,8C), V(29,EE,EE,C7), V(D3,B8,B8,6B), V(3C,14,14,28), \
    V(79,DE,DE,A7), V(E2,5E,5E,BC), V(1D,0B,0B,16), V(76,DB,DB,AD), \
    V(3B,E0,E0,DB), V(56,32,32,64), V(4E,3A,3A,74), V(1E,0A,0A,14), \
    V(DB,49,49,92), V(0A,06,06,0C), V(6C,24,24,48), V(E4,5C,5C,B8), \
    V(5D,C2,C2,9F), V(6E,D3,D3,BD), V(EF,AC,AC,43), V(A6,62,62,C4), \
    V(A8,91,91,39), V(A4,95,95,31), V(37,E4,E4,D3), V(8B,79,79,F2), \
    V(32,E7,E7,D5), V(43,C8,C8,8B), V(59,37,37,6E), V(B7,6D,6D,DA), \
    V(8C,8D,8D,01), V(64,D5,D5,B1), V(D2,4E,4E,9C), V(E0,A9,A9,49), \
    V(B4,6C,6C,D8), V(FA,56,56,AC), V(07,F4,F4,F3), V(25,EA,EA,CF), \
    V(AF,65,65,CA), V(8E,7A,7A,F4), V(E9,AE,AE,47), V(18,08,08,10), \
    V(D5,BA,BA,6F), V(88,78,78,F0), V(6F,25,25,4A), V(72,2E,2E,5C), \
    V(24,1C,1C,38), V(F1,A6,A6,57), V(C7,B4,B4,73), V(51,C6,C6,97), \
    V(23,E8,E8,CB), V(7C,DD,DD,A1), V(9C,74,74,E8), V(21,1F,1F,3E), \
    V(DD,4B,4B,96), V(DC,BD,BD,61), V(86,8B,8B,0D), V(85,8A,8A,0F), \
    V(90,70,70,E0), V(42,3E,3E,7C), V(C4,B5,B5,71), V(AA,66,66,CC), \
    V(D8,48,48,90), V(05,03,03,06), V(01,F6,F6,F7), V(12,0E,0E,1C), \
    V(A3,61,61,C2), V(5F,35,35,6A), V(F9,57,57,AE), V(D0,B9,B9,69), \
    V(91,86,86,17), V(58,C1,C1,99), V(27,1D,1D,3A), V(B9,9E,9E,27), \
    V(38,E1,E1,D9), V(13,F8,F8,EB), V(B3,98,98,2B), V(33,11,11,22), \
    V(BB,69,69,D2), V(70,D9,D9,A9), V(89,8E,8E,07), V(A7,94,94,33), \
    V(B6,9B,9B,2D), V(22,1E,1E,3C), V(92,87,87,15), V(20,E9,E9,C9), \
    V(49,CE,CE,87), V(FF,55,55,AA), V(78,28,28,50), V(7A,DF,DF,A5), \
    V(8F,8C,8C,03), V(F8,A1,A1,59), V(80,89,89,09), V(17,0D,0D,1A), \
    V(DA,BF,BF,65), V(31,E6,E6,D7), V(C6,42,42,84), V(B8,68,68,D0), \
    V(C3,41,41,82), V(B0,99,99,29), V(77,2D,2D,5A), V(11,0F,0F,1E), \
    V(CB,B0,B0,7B), V(FC,54,54,A8), V(D6,BB,BB,6D), V(3A,16,16,2C)

#define V(a,b,c,d) 0x##a##b##c##d
static const uint32_t FT0[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
static const uint32_t FT1[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const uint32_t FT2[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const uint32_t FT3[256] = { FT };
#undef V

#undef FT

/*
 * Reverse S-box
 */
static const unsigned char RSb[256] =
{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

/*
 * Reverse tables
 */
#define RT \
\
    V(50,A7,F4,51), V(53,65,41,7E), V(C3,A4,17,1A), V(96,5E,27,3A), \
    V(CB,6B,AB,3B), V(F1,45,9D,1F), V(AB,58,FA,AC), V(93,03,E3,4B), \
    V(55,FA,30,20), V(F6,6D,76,AD), V(91,76,CC,88), V(25,4C,02,F5), \
    V(FC,D7,E5,4F), V(D7,CB,2A,C5), V(80,44,35,26), V(8F,A3,62,B5), \
    V(49,5A,B1,DE), V(67,1B,BA,25), V(98,0E,EA,45), V(E1,C0,FE,5D), \
    V(02,75,2F,C3), V(12,F0,4C,81), V(A3,97,46,8D), V(C6,F9,D3,6B), \
    V(E7,5F,8F,03), V(95,9C,92,15), V(EB,7A,6D,BF), V(DA,59,52,95), \
    V(2D,83,BE,D4), V(D3,21,74,58), V(29,69,E0,49), V(44,C8,C9,8E), \
    V(6A,89,C2,75), V(78,79,8E,F4), V(6B,3E,58,99), V(DD,71,B9,27), \
    V(B6,4F,E1,BE), V(17,AD,88,F0), V(66,AC,20,C9), V(B4,3A,CE,7D), \
    V(18,4A,DF,63), V(82,31,1A,E5), V(60,33,51,97), V(45,7F,53,62), \
    V(E0,77,64,B1), V(84,AE,6B,BB), V(1C,A0,81,FE), V(94,2B,08,F9), \
    V(58,68,48,70), V(19,FD,45,8F), V(87,6C,DE,94), V(B7,F8,7B,52), \
    V(23,D3,73,AB), V(E2,02,4B,72), V(57,8F,1F,E3), V(2A,AB,55,66), \
    V(07,28,EB,B2), V(03,C2,B5,2F), V(9A,7B,C5,86), V(A5,08,37,D3), \
    V(F2,87,28,30), V(B2,A5,BF,23), V(BA,6A,03,02), V(5C,82,16,ED), \
    V(2B,1C,CF,8A), V(92,B4,79,A7), V(F0,F2,07,F3), V(A1,E2,69,4E), \
    V(CD,F4,DA,65), V(D5,BE,05,06), V(1F,62,34,D1), V(8A,FE,A6,C4), \
    V(9D,53,2E,34), V(A0,55,F3,A2), V(32,E1,8A,05), V(75,EB,F6,A4), \
    V(39,EC,83,0B), V(AA,EF,60,40), V(06,9F,71,5E), V(51,10,6E,BD), \
    V(F9,8A,21,3E), V(3D,06,DD,96), V(AE,05,3E,DD), V(46,BD,E6,4D), \
    V(B5,8D,54,91), V(05,5D,C4,71), V(6F,D4,06,04), V(FF,15,50,60), \
    V(24,FB,98,19), V(97,E9,BD,D6), V(CC,43,40,89), V(77,9E,D9,67), \
    V(BD,42,E8,B0), V(88,8B,89,07), V(38,5B,19,E7), V(DB,EE,C8,79), \
    V(47,0A,7C,A1), V(E9,0F,42,7C), V(C9,1E,84,F8), V(00,00,00,00), \
    V(83,86,80,09), V(48,ED,2B,32), V(AC,70,11,1E), V(4E,72,5A,6C), \
    V(FB,FF,0E,FD), V(56,38,85,0F), V(1E,D5,AE,3D), V(27,39,2D,36), \
    V(64,D9,0F,0A), V(21,A6,5C,68), V(D1,54,5B,9B), V(3A,2E,36,24), \
    V(B1,67,0A,0C), V(0F,E7,57,93), V(D2,96,EE,B4), V(9E,91,9B,1B), \
    V(4F,C5,C0,80), V(A2,20,DC,61), V(69,4B,77,5A), V(16,1A,12,1C), \
    V(0A,BA,93,E2), V(E5,2A,A0,C0), V(43,E0,22,3C), V(1D,17,1B,12), \
    V(0B,0D,09,0E), V(AD,C7,8B,F2), V(B9,A8,B6,2D), V(C8,A9,1E,14), \
    V(85,19,F1,57), V(4C,07,75,AF), V(BB,DD,99,EE), V(FD,60,7F,A3), \
    V(9F,26,01,F7), V(BC,F5,72,5C), V(C5,3B,66,44), V(34,7E,FB,5B), \
    V(76,29,43,8B), V(DC,C6,23,CB), V(68,FC,ED,B6), V(63,F1,E4,B8), \
    V(CA,DC,31,D7), V(10,85,63,42), V(40,22,97,13), V(20,11,C6,84), \
    V(7D,24,4A,85), V(F8,3D,BB,D2), V(11,32,F9,AE), V(6D,A1,29,C7), \
    V(4B,2F,9E,1D), V(F3,30,B2,DC), V(EC,52,86,0D), V(D0,E3,C1,77), \
    V(6C,16,B3,2B), V(99,B9,70,A9), V(FA,48,94,11), V(22,64,E9,47), \
    V(C4,8C,FC,A8), V(1A,3F,F0,A0), V(D8,2C,7D,56), V(EF,90,33,22), \
    V(C7,4E,49,87), V(C1,D1,38,D9), V(FE,A2,CA,8C), V(36,0B,D4,98), \
    V(CF,81,F5,A6), V(28,DE,7A,A5), V(26,8E,B7,DA), V(A4,BF,AD,3F), \
    V(E4,9D,3A,2C), V(0D,92,78,50), V(9B,CC,5F,6A), V(62,46,7E,54), \
    V(C2,13,8D,F6), V(E8,B8,D8,90), V(5E,F7,39,2E), V(F5,AF,C3,82), \
    V(BE,80,5D,9F), V(7C,93,D0,69), V(A9,2D,D5,6F), V(B3,12,25,CF), \
    V(3B,99,AC,C8), V(A7,7D,18,10), V(6E,63,9C,E8), V(7B,BB,3B,DB), \
    V(09,78,26,CD), V(F4,18,59,6E), V(01,B7,9A,EC), V(A8,9A,4F,83), \
    V(65,6E,95,E6), V(7E,E6,FF,AA), V(08,CF,BC,21), V(E6,E8,15,EF), \
    V(D9,9B,E7,BA), V(CE,36,6F,4A), V(D4,09,9F,EA), V(D6,7C,B0,29), \
    V(AF,B2,A4,31), V(31,23,3F,2A), V(30,94,A5,C6), V(C0,66,A2,35), \
    V(37,BC,4E,74), V(A6,CA,82,FC), V(B0,D0,90,E0), V(15,D8,A7,33), \
    V(4A,98,04,F1), V(F7,DA,EC,41), V(0E,50,CD,7F), V(2F,F6,91,17), \
    V(8D,D6,4D,76), V(4D,B0,EF,43), V(54,4D,AA,CC), V(DF,04,96,E4), \
    V(E3,B5,D1,9E), V(1B,88,6A,4C), V(B8,1F,2C,C1), V(7F,51,65,46), \
    V(04,EA,5E,9D), V(5D,35,8C,01), V(73,74,87,FA), V(2E,41,0B,FB), \
    V(5A,1D,67,B3), V(52,D2,DB,92), V(33,56,10,E9), V(13,47,D6,6D), \
    V(8C,61,D7,9A), V(7A,0C,A1,37), V(8E,14,F8,59), V(89,3C,13,EB), \
    V(EE,27,A9,CE), V(35,C9,61,B7), V(ED,E5,1C,E1), V(3C,B1,47,7A), \
    V(59,DF,D2,9C), V(3F,73,F2,55), V(79,CE,14,18), V(BF,37,C7,73), \
    V(EA,CD,F7,53), V(5B,AA,FD,5F), V(14,6F,3D,DF), V(86,DB,44,78), \
    V(81,F3,AF,CA), V(3E,C4,68,B9), V(2C,34,24,38), V(5F,40,A3,C2), \
    V(72,C3,1D,16), V(0C,25,E2,BC), V(8B,49,3C,28), V(41,95,0D,FF), \
    V(71,01,A8,39), V(DE,B3,0C,08), V(9C,E4,B4,D8), V(90,C1,56,64), \
    V(61,84,CB,7B), V(70,B6,32,D5), V(74,5C,6C,48), V(42,57,B8,D0)

#define V(a,b,c,d) 0x##a##b##c##d
static const uint32_t RT0[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
static const uint32_t RT1[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const uint32_t RT2[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const uint32_t RT3[256] = { RT };
#undef V

#undef RT

/*
 * Round constants
 */
static const uint32_t RCON[10] =
{
    0x00000001, 0x00000002, 0x00000004, 0x00000008,
    0x00000010, 0x00000020, 0x00000040, 0x00000080,
    0x0000001B, 0x00000036
};

#else /* MBEDTLS_AES_ROM_TABLES */

/*
 * Forward S-box & tables
 */
static unsigned char FSb[256];
static uint32_t FT0[256];
static uint32_t FT1[256];
static uint32_t FT2[256];
static uint32_t FT3[256];

/*
 * Reverse S-box & tables
 */
static unsigned char RSb[256];
static uint32_t RT0[256];
static uint32_t RT1[256];
static uint32_t RT2[256];
static uint32_t RT3[256];

/*
 * Round constants
 */
static uint32_t RCON[10];

/*
 * Tables generation code
 */
#define ROTL8(x) ( ( x << 8 ) & 0xFFFFFFFF ) | ( x >> 24 )
#define XTIME(x) ( ( x << 1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( x && y ) ? pow[(log[x]+log[y]) % 255] : 0 )

static int aes_init_done = 0;

static void aes_gen_tables( void )
{
    int i, x, y, z;
    int pow[256];
    int log[256];

    /*
     * compute pow and log tables over GF(2^8)
     */
    for( i = 0, x = 1; i < 256; i++ )
    {
        pow[i] = x;
        log[x] = i;
        x = ( x ^ XTIME( x ) ) & 0xFF;
    }

    /*
     * calculate the round constants
     */
    for( i = 0, x = 1; i < 10; i++ )
    {
        RCON[i] = (uint32_t) x;
        x = XTIME( x ) & 0xFF;
    }

    /*
     * generate the forward and reverse S-boxes
     */
    FSb[0x00] = 0x63;
    RSb[0x63] = 0x00;

    for( i = 1; i < 256; i++ )
    {
        x = pow[255 - log[i]];

        y  = x; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y ^ 0x63;

        FSb[i] = (unsigned char) x;
        RSb[x] = (unsigned char) i;
    }

    /*
     * generate the forward and reverse tables
     */
    for( i = 0; i < 256; i++ )
    {
        x = FSb[i];
        y = XTIME( x ) & 0xFF;
        z =  ( y ^ x ) & 0xFF;

        FT0[i] = ( (uint32_t) y       ) ^
                 ( (uint32_t) x <<  8 ) ^
                 ( (uint32_t) x << 16 ) ^
                 ( (uint32_t) z << 24 );

        FT1[i] = ROTL8( FT0[i] );
        FT2[i] = ROTL8( FT1[i] );
        FT3[i] = ROTL8( FT2[i] );

        x = RSb[i];

        RT0[i] = ( (uint32_t) MUL( 0x0E, x )       ) ^
                 ( (uint32_t) MUL( 0x09, x ) <<  8 ) ^
                 ( (uint32_t) MUL( 0x0D, x ) << 16 ) ^
                 ( (uint32_t) MUL( 0x0B, x ) << 24 );

        RT1[i] = ROTL8( RT0[i] );
        RT2[i] = ROTL8( RT1[i] );
        RT3[i] = ROTL8( RT2[i] );
    }
}

#endif /* MBEDTLS_AES_ROM_TABLES */

void mbedtls_aes_init( mbedtls_aes_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_aes_context ) );
}

void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_zeroize( ctx, sizeof( mbedtls_aes_context ) );
}

/*
 * AES key schedule (encryption)
 */
#if !defined(MBEDTLS_AES_SETKEY_ENC_ALT)
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    unsigned int i;
    uint32_t *RK;

#if !defined(MBEDTLS_AES_ROM_TABLES)
    if( aes_init_done == 0 )
    {
        aes_gen_tables();
        aes_init_done = 1;

    }
#endif

    switch( keybits )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_PADLOCK_ALIGN16)
    if( aes_padlock_ace == -1 )
        aes_padlock_ace = mbedtls_padlock_has_support( MBEDTLS_PADLOCK_ACE );

    if( aes_padlock_ace )
        ctx->rk = RK = MBEDTLS_PADLOCK_ALIGN16( ctx->buf );
    else
#endif
    ctx->rk = RK = ctx->buf;

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
        return( mbedtls_aesni_setkey_enc( (unsigned char *) ctx->rk, key, keybits ) );
#endif

    for( i = 0; i < ( keybits >> 5 ); i++ )
    {
        GET_UINT32_LE( RK[i], key, i << 2 );
    }

    switch( ctx->nr )
    {
        case 10:

            for( i = 0; i < 10; i++, RK += 4 )
            {
                RK[4]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[3] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[3]       ) & 0xFF ] << 24 );

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

        case 12:

            for( i = 0; i < 8; i++, RK += 6 )
            {
                RK[6]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[5] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[5]       ) & 0xFF ] << 24 );

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:

            for( i = 0; i < 7; i++, RK += 8 )
            {
                RK[8]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[7] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[7]       ) & 0xFF ] << 24 );

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                ( (uint32_t) FSb[ ( RK[11]       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[11] >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 24 ) & 0xFF ] << 24 );

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;
    }

    return( 0 );
}
#endif /* !MBEDTLS_AES_SETKEY_ENC_ALT */

/*
 * AES key schedule (decryption)
 */
#if !defined(MBEDTLS_AES_SETKEY_DEC_ALT)
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    int i, j, ret;
    mbedtls_aes_context cty;
    uint32_t *RK;
    uint32_t *SK;

    mbedtls_aes_init( &cty );

#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_PADLOCK_ALIGN16)
    if( aes_padlock_ace == -1 )
        aes_padlock_ace = mbedtls_padlock_has_support( MBEDTLS_PADLOCK_ACE );

    if( aes_padlock_ace )
        ctx->rk = RK = MBEDTLS_PADLOCK_ALIGN16( ctx->buf );
    else
#endif
    ctx->rk = RK = ctx->buf;

    /* Also checks keybits */
    if( ( ret = mbedtls_aes_setkey_enc( &cty, key, keybits ) ) != 0 )
        goto exit;

    ctx->nr = cty.nr;

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
    {
        mbedtls_aesni_inverse_key( (unsigned char *) ctx->rk,
                           (const unsigned char *) cty.rk, ctx->nr );
        goto exit;
    }
#endif

    SK = cty.rk + cty.nr * 4;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    for( i = ctx->nr - 1, SK -= 8; i > 0; i--, SK -= 8 )
    {
        for( j = 0; j < 4; j++, SK++ )
        {
            *RK++ = RT0[ FSb[ ( *SK       ) & 0xFF ] ] ^
                    RT1[ FSb[ ( *SK >>  8 ) & 0xFF ] ] ^
                    RT2[ FSb[ ( *SK >> 16 ) & 0xFF ] ] ^
                    RT3[ FSb[ ( *SK >> 24 ) & 0xFF ] ];
        }
    }

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

exit:
    mbedtls_aes_free( &cty );

    return( ret );
}
#endif /* !MBEDTLS_AES_SETKEY_DEC_ALT */

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ FT0[ ( Y0       ) & 0xFF ] ^   \
                 FT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ FT0[ ( Y1       ) & 0xFF ] ^   \
                 FT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y0 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ FT0[ ( Y2       ) & 0xFF ] ^   \
                 FT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ FT0[ ( Y3       ) & 0xFF ] ^   \
                 FT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y2 >> 24 ) & 0xFF ];    \
}

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ RT0[ ( Y0       ) & 0xFF ] ^   \
                 RT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ RT0[ ( Y1       ) & 0xFF ] ^   \
                 RT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y2 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ RT0[ ( Y2       ) & 0xFF ] ^   \
                 RT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ RT0[ ( Y3       ) & 0xFF ] ^   \
                 RT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y0 >> 24 ) & 0xFF ];    \
}

/*
 * AES-ECB block encryption
 */
#if !defined(MBEDTLS_AES_ENCRYPT_ALT)
void mbedtls_aes_encrypt( mbedtls_aes_context *ctx,
                          const unsigned char input[16],
                          unsigned char output[16] )
{
    int i;
    uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->rk;

    GET_UINT32_LE( X0, input,  0 ); X0 ^= *RK++;
    GET_UINT32_LE( X1, input,  4 ); X1 ^= *RK++;
    GET_UINT32_LE( X2, input,  8 ); X2 ^= *RK++;
    GET_UINT32_LE( X3, input, 12 ); X3 ^= *RK++;

    for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
    {
        AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
        AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
    }

    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

    X0 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y0       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

    X1 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y1       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );

    X2 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y2       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

    X3 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y3       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );

    PUT_UINT32_LE( X0, output,  0 );
    PUT_UINT32_LE( X1, output,  4 );
    PUT_UINT32_LE( X2, output,  8 );
    PUT_UINT32_LE( X3, output, 12 );
}
#endif /* !MBEDTLS_AES_ENCRYPT_ALT */

/*
 * AES-ECB block decryption
 */
#if !defined(MBEDTLS_AES_DECRYPT_ALT)
void mbedtls_aes_decrypt( mbedtls_aes_context *ctx,
                          const unsigned char input[16],
                          unsigned char output[16] )
{
    int i;
    uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->rk;

    GET_UINT32_LE( X0, input,  0 ); X0 ^= *RK++;
    GET_UINT32_LE( X1, input,  4 ); X1 ^= *RK++;
    GET_UINT32_LE( X2, input,  8 ); X2 ^= *RK++;
    GET_UINT32_LE( X3, input, 12 ); X3 ^= *RK++;

    for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
    {
        AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
        AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
    }

    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

    X0 = *RK++ ^ \
            ( (uint32_t) RSb[ ( Y0       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

    X1 = *RK++ ^ \
            ( (uint32_t) RSb[ ( Y1       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );

    X2 = *RK++ ^ \
            ( (uint32_t) RSb[ ( Y2       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

    X3 = *RK++ ^ \
            ( (uint32_t) RSb[ ( Y3       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );

    PUT_UINT32_LE( X0, output,  0 );
    PUT_UINT32_LE( X1, output,  4 );
    PUT_UINT32_LE( X2, output,  8 );
    PUT_UINT32_LE( X3, output, 12 );
}
#endif /* !MBEDTLS_AES_DECRYPT_ALT */

/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] )
{
#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
        return( mbedtls_aesni_crypt_ecb( ctx, mode, input, output ) );
#endif

#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_HAVE_X86)
    if( aes_padlock_ace )
    {
        if( mbedtls_padlock_xcryptecb( ctx, mode, input, output ) == 0 )
            return( 0 );

        // If padlock data misaligned, we just fall back to
        // unaccelerated mode
        //
    }
#endif

    if( mode == MBEDTLS_AES_ENCRYPT )
        mbedtls_aes_encrypt( ctx, input, output );
    else
        mbedtls_aes_decrypt( ctx, input, output );

    return( 0 );
}



/*
 * AES-CTR buffer encryption/decryption
 */
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c, i;
    size_t n = *nc_off;

    while( length-- )
    {
        if( n == 0 ) {
            mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, nonce_counter, stream_block );

            for( i = 16; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        c = *input++;
        *output++ = (unsigned char)( c ^ stream_block[n] );

        n = ( n + 1 ) & 0x0F;
    }

    *nc_off = n;

    return( 0 );
}
/*-
 * Copyright 2005,2007,2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/types.h>
#include <stdint.h>
#include <string.h>

static inline uint32_t
be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;

	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
	    ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static inline void
be32enc(void *pp, uint32_t x)
{
	uint8_t * p = (uint8_t *)pp;

	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}

/*
static inline uint64_t
be64dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;

	return ((uint64_t)(p[7]) + ((uint64_t)(p[6]) << 8) +
	    ((uint64_t)(p[5]) << 16) + ((uint64_t)(p[4]) << 24) +
	    ((uint64_t)(p[3]) << 32) + ((uint64_t)(p[2]) << 40) +
	    ((uint64_t)(p[1]) << 48) + ((uint64_t)(p[0]) << 56));
}

static inline void
be64enc(void *pp, uint64_t x)
{
	uint8_t * p = (uint8_t *)pp;

	p[7] = x & 0xff;
	p[6] = (x >> 8) & 0xff;
	p[5] = (x >> 16) & 0xff;
	p[4] = (x >> 24) & 0xff;
	p[3] = (x >> 32) & 0xff;
	p[2] = (x >> 40) & 0xff;
	p[1] = (x >> 48) & 0xff;
	p[0] = (x >> 56) & 0xff;
}

static inline uint32_t
le32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;

	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
	    ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void
le32enc(void *pp, uint32_t x)
{
	uint8_t * p = (uint8_t *)pp;

	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
}

static inline uint64_t
le64dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;

	return ((uint64_t)(p[0]) + ((uint64_t)(p[1]) << 8) +
	    ((uint64_t)(p[2]) << 16) + ((uint64_t)(p[3]) << 24) +
	    ((uint64_t)(p[4]) << 32) + ((uint64_t)(p[5]) << 40) +
	    ((uint64_t)(p[6]) << 48) + ((uint64_t)(p[7]) << 56));
}

static inline void
le64enc(void *pp, uint64_t x)
{
	uint8_t * p = (uint8_t *)pp;

	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
	p[4] = (x >> 32) & 0xff;
	p[5] = (x >> 40) & 0xff;
	p[6] = (x >> 48) & 0xff;
	p[7] = (x >> 56) & 0xff;
}
*/

typedef struct SHA256Context {
	uint32_t state[8];
	uint32_t count[2];
	unsigned char buf[64];
} SHA256_CTX;

typedef struct HMAC_SHA256Context {
	SHA256_CTX ictx;
	SHA256_CTX octx;
} HMAC_SHA256_CTX;

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static void
be32enc_vect(unsigned char *dst, const uint32_t *src, size_t len)
{
	size_t i;

	for (i = 0; i < len / 4; i++)
		be32enc(dst + i * 4, src[i]);
}

/*
 * Decode a big-endian length len vector of (unsigned char) into a length
 * len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
 */
static void
be32dec_vect(uint32_t *dst, const unsigned char *src, size_t len)
{
	size_t i;

	for (i = 0; i < len / 4; i++)
		dst[i] = be32dec(src + i * 4);
}

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)	((x & (y ^ z)) ^ z)
#define Maj(x, y, z)	((x & (y | z)) | (y & z))
#define SHR(x, n)	(x >> n)
#define ROTR(x, n)	((x >> n) | (x << (32 - n)))
#define S0(x)		(ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)		(ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)		(ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)		(ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k)			\
	t0 = h + S1(e) + Ch(e, f, g) + k;		\
	t1 = S0(a) + Maj(a, b, c);			\
	d += t0;					\
	h  = t0 + t1;

/* Adjusted round function for rotating state */
#define RNDr(S, W, i, k)			\
	RND(S[(64 - i) % 8], S[(65 - i) % 8],	\
	    S[(66 - i) % 8], S[(67 - i) % 8],	\
	    S[(68 - i) % 8], S[(69 - i) % 8],	\
	    S[(70 - i) % 8], S[(71 - i) % 8],	\
	    W[i] + k)

/*
 * SHA256 block compression function.  The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
static void
SHA256_Transform(uint32_t * state, const unsigned char block[64])
{
	uint32_t W[64];
	uint32_t S[8];
	uint32_t t0, t1;
	int i;

	/* 1. Prepare message schedule W. */
	be32dec_vect(W, block, 64);
	for (i = 16; i < 64; i++)
		W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];

	/* 2. Initialize working variables. */
	memcpy(S, state, 32);

	/* 3. Mix. */
	RNDr(S, W, 0, 0x428a2f98);
	RNDr(S, W, 1, 0x71374491);
	RNDr(S, W, 2, 0xb5c0fbcf);
	RNDr(S, W, 3, 0xe9b5dba5);
	RNDr(S, W, 4, 0x3956c25b);
	RNDr(S, W, 5, 0x59f111f1);
	RNDr(S, W, 6, 0x923f82a4);
	RNDr(S, W, 7, 0xab1c5ed5);
	RNDr(S, W, 8, 0xd807aa98);
	RNDr(S, W, 9, 0x12835b01);
	RNDr(S, W, 10, 0x243185be);
	RNDr(S, W, 11, 0x550c7dc3);
	RNDr(S, W, 12, 0x72be5d74);
	RNDr(S, W, 13, 0x80deb1fe);
	RNDr(S, W, 14, 0x9bdc06a7);
	RNDr(S, W, 15, 0xc19bf174);
	RNDr(S, W, 16, 0xe49b69c1);
	RNDr(S, W, 17, 0xefbe4786);
	RNDr(S, W, 18, 0x0fc19dc6);
	RNDr(S, W, 19, 0x240ca1cc);
	RNDr(S, W, 20, 0x2de92c6f);
	RNDr(S, W, 21, 0x4a7484aa);
	RNDr(S, W, 22, 0x5cb0a9dc);
	RNDr(S, W, 23, 0x76f988da);
	RNDr(S, W, 24, 0x983e5152);
	RNDr(S, W, 25, 0xa831c66d);
	RNDr(S, W, 26, 0xb00327c8);
	RNDr(S, W, 27, 0xbf597fc7);
	RNDr(S, W, 28, 0xc6e00bf3);
	RNDr(S, W, 29, 0xd5a79147);
	RNDr(S, W, 30, 0x06ca6351);
	RNDr(S, W, 31, 0x14292967);
	RNDr(S, W, 32, 0x27b70a85);
	RNDr(S, W, 33, 0x2e1b2138);
	RNDr(S, W, 34, 0x4d2c6dfc);
	RNDr(S, W, 35, 0x53380d13);
	RNDr(S, W, 36, 0x650a7354);
	RNDr(S, W, 37, 0x766a0abb);
	RNDr(S, W, 38, 0x81c2c92e);
	RNDr(S, W, 39, 0x92722c85);
	RNDr(S, W, 40, 0xa2bfe8a1);
	RNDr(S, W, 41, 0xa81a664b);
	RNDr(S, W, 42, 0xc24b8b70);
	RNDr(S, W, 43, 0xc76c51a3);
	RNDr(S, W, 44, 0xd192e819);
	RNDr(S, W, 45, 0xd6990624);
	RNDr(S, W, 46, 0xf40e3585);
	RNDr(S, W, 47, 0x106aa070);
	RNDr(S, W, 48, 0x19a4c116);
	RNDr(S, W, 49, 0x1e376c08);
	RNDr(S, W, 50, 0x2748774c);
	RNDr(S, W, 51, 0x34b0bcb5);
	RNDr(S, W, 52, 0x391c0cb3);
	RNDr(S, W, 53, 0x4ed8aa4a);
	RNDr(S, W, 54, 0x5b9cca4f);
	RNDr(S, W, 55, 0x682e6ff3);
	RNDr(S, W, 56, 0x748f82ee);
	RNDr(S, W, 57, 0x78a5636f);
	RNDr(S, W, 58, 0x84c87814);
	RNDr(S, W, 59, 0x8cc70208);
	RNDr(S, W, 60, 0x90befffa);
	RNDr(S, W, 61, 0xa4506ceb);
	RNDr(S, W, 62, 0xbef9a3f7);
	RNDr(S, W, 63, 0xc67178f2);

	/* 4. Mix local working variables into global state */
	for (i = 0; i < 8; i++)
		state[i] += S[i];

	/* Clean the stack. */
	memset(W, 0, 256);
	memset(S, 0, 32);
	t0 = t1 = 0;
}

/* SHA-256 initialization.  Begins a SHA-256 operation. */
void
SHA256_Init(SHA256_CTX * ctx)
{

	/* Zero bits processed so far */
	ctx->count[0] = ctx->count[1] = 0;

	/* Magic initialization constants */
	ctx->state[0] = 0x6A09E667;
	ctx->state[1] = 0xBB67AE85;
	ctx->state[2] = 0x3C6EF372;
	ctx->state[3] = 0xA54FF53A;
	ctx->state[4] = 0x510E527F;
	ctx->state[5] = 0x9B05688C;
	ctx->state[6] = 0x1F83D9AB;
	ctx->state[7] = 0x5BE0CD19;
}

/* Add bytes into the hash */
void
SHA256_Update(SHA256_CTX * ctx, const void *in, size_t len)
{
	uint32_t bitlen[2];
	uint32_t r;
	const unsigned char *src = in;

	/* Number of bytes left in the buffer from previous updates */
	r = (ctx->count[1] >> 3) & 0x3f;

	/* Convert the length into a number of bits */
	bitlen[1] = ((uint32_t)len) << 3;
	bitlen[0] = (uint32_t)(len >> 29);

	/* Update number of bits */
	if ((ctx->count[1] += bitlen[1]) < bitlen[1])
		ctx->count[0]++;
	ctx->count[0] += bitlen[0];

	/* Handle the case where we don't need to perform any transforms */
	if (len < 64 - r) {
		memcpy(&ctx->buf[r], src, len);
		return;
	}

	/* Finish the current block */
	memcpy(&ctx->buf[r], src, 64 - r);
	SHA256_Transform(ctx->state, ctx->buf);
	src += 64 - r;
	len -= 64 - r;

	/* Perform complete blocks */
	while (len >= 64) {
		SHA256_Transform(ctx->state, src);
		src += 64;
		len -= 64;
	}

	/* Copy left over data into buffer */
	memcpy(ctx->buf, src, len);
}

/* Add padding and terminating bit-count. */
static void
SHA256_Pad(SHA256_CTX * ctx)
{
	unsigned char len[8];
	uint32_t r, plen;
  unsigned char PAD[64] = {
  	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };


	/*
	 * Convert length to a vector of bytes -- we do this now rather
	 * than later because the length will change after we pad.
	 */
	be32enc_vect(len, ctx->count, 8);

	/* Add 1--64 bytes so that the resulting length is 56 mod 64 */
	r = (ctx->count[1] >> 3) & 0x3f;
	plen = (r < 56) ? (56 - r) : (120 - r);
	SHA256_Update(ctx, PAD, (size_t)plen);

	/* Add the terminating bit-count */
	SHA256_Update(ctx, len, 8);
}

/*
 * SHA-256 finalization.  Pads the input data, exports the hash value,
 * and clears the context state.
 */
void
SHA256_Final(unsigned char digest[32], SHA256_CTX * ctx)
{

	/* Add padding */
	SHA256_Pad(ctx);

	/* Write the hash */
	be32enc_vect(digest, ctx->state, 32);

	/* Clear the context state */
	memset((void *)ctx, 0, sizeof(*ctx));
}

/* Initialize an HMAC-SHA256 operation with the given key. */
void
HMAC_SHA256_Init(HMAC_SHA256_CTX * ctx, const void * _K, size_t Klen)
{
	unsigned char pad[64];
	unsigned char khash[32];
	const unsigned char * K = _K;
	size_t i;

	/* If Klen > 64, the key is really SHA256(K). */
	if (Klen > 64) {
		SHA256_Init(&ctx->ictx);
		SHA256_Update(&ctx->ictx, K, Klen);
		SHA256_Final(khash, &ctx->ictx);
		K = khash;
		Klen = 32;
	}

	/* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
	SHA256_Init(&ctx->ictx);
	memset(pad, 0x36, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	SHA256_Update(&ctx->ictx, pad, 64);

	/* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
	SHA256_Init(&ctx->octx);
	memset(pad, 0x5c, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	SHA256_Update(&ctx->octx, pad, 64);

	/* Clean the stack. */
	memset(khash, 0, 32);
}

/* Add bytes to the HMAC-SHA256 operation. */
void
HMAC_SHA256_Update(HMAC_SHA256_CTX * ctx, const void *in, size_t len)
{

	/* Feed data to the inner SHA256 operation. */
	SHA256_Update(&ctx->ictx, in, len);
}

/* Finish an HMAC-SHA256 operation. */
void
HMAC_SHA256_Final(unsigned char digest[32], HMAC_SHA256_CTX * ctx)
{
	unsigned char ihash[32];

	/* Finish the inner SHA256 operation. */
	SHA256_Final(ihash, &ctx->ictx);

	/* Feed the inner hash to the outer SHA256 operation. */
	SHA256_Update(&ctx->octx, ihash, 32);

	/* Finish the outer SHA256 operation. */
	SHA256_Final(digest, &ctx->octx);

	/* Clean the stack. */
	memset(ihash, 0, 32);
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void
PBKDF2_SHA256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
    size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
	HMAC_SHA256_CTX PShctx, hctx;
	size_t i;
	uint8_t ivec[4];
	uint8_t U[32];
	uint8_t T[32];
	uint64_t j;
	int k;
	size_t clen;

	/* Compute HMAC state after processing P and S. */
	HMAC_SHA256_Init(&PShctx, passwd, passwdlen);
	HMAC_SHA256_Update(&PShctx, salt, saltlen);

	/* Iterate through the blocks. */
	for (i = 0; i * 32 < dkLen; i++) {
		/* Generate INT(i + 1). */
		be32enc(ivec, (uint32_t)(i + 1));

		/* Compute U_1 = PRF(P, S || INT(i)). */
		memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
		HMAC_SHA256_Update(&hctx, ivec, 4);
		HMAC_SHA256_Final(U, &hctx);

		/* T_i = U_1 ... */
		memcpy(T, U, 32);

		for (j = 2; j <= c; j++) {
			/* Compute U_j. */
			HMAC_SHA256_Init(&hctx, passwd, passwdlen);
			HMAC_SHA256_Update(&hctx, U, 32);
			HMAC_SHA256_Final(U, &hctx);

			/* ... xor U_j ... */
			for (k = 0; k < 32; k++)
				T[k] ^= U[k];
		}

		/* Copy as many bytes as necessary into buf. */
		clen = dkLen - i * 32;
		if (clen > 32)
			clen = 32;
		memcpy(&buf[i * 32], T, clen);
	}

	/* Clean PShctx, since we never called _Final on it. */
	memset(&PShctx, 0, sizeof(HMAC_SHA256_CTX));
}
void sha256( const unsigned char *input, size_t ilen,
             unsigned char output[32], int is224)
{
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, input, ilen);
  SHA256_Final(output, &ctx);
}

void sha256_hmac( const unsigned char *key, size_t keylen,
                  const unsigned char *input, size_t ilen,
                  unsigned char output[32], int is224 )
{
  HMAC_SHA256_CTX hctx;
  HMAC_SHA256_Init(&hctx, key, keylen);
  HMAC_SHA256_Update(&hctx, input, ilen);
  HMAC_SHA256_Final(output, &hctx);
}

void hmac_256(const unsigned char *key, size_t keylen, const unsigned char *input, size_t ilen, unsigned char output[32])
{
  sha256_hmac(key, keylen, input, ilen, output, 0);
}
/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"
#include "uECC_vli.h"

#ifndef uECC_RNG_MAX_TRIES
    #define uECC_RNG_MAX_TRIES 64
#endif

#if uECC_ENABLE_VLI_API
    #define uECC_VLI_API
#else
    #define uECC_VLI_API static
#endif

#define CONCATX(a, ...) a ## __VA_ARGS__
#define CONCAT(a, ...) CONCATX(a, __VA_ARGS__)

#define STRX(a) #a
#define STR(a) STRX(a)

#define EVAL(...)  EVAL1(EVAL1(EVAL1(EVAL1(__VA_ARGS__))))
#define EVAL1(...) EVAL2(EVAL2(EVAL2(EVAL2(__VA_ARGS__))))
#define EVAL2(...) EVAL3(EVAL3(EVAL3(EVAL3(__VA_ARGS__))))
#define EVAL3(...) EVAL4(EVAL4(EVAL4(EVAL4(__VA_ARGS__))))
#define EVAL4(...) __VA_ARGS__

#define DEC_1  0
#define DEC_2  1
#define DEC_3  2
#define DEC_4  3
#define DEC_5  4
#define DEC_6  5
#define DEC_7  6
#define DEC_8  7
#define DEC_9  8
#define DEC_10 9
#define DEC_11 10
#define DEC_12 11
#define DEC_13 12
#define DEC_14 13
#define DEC_15 14
#define DEC_16 15
#define DEC_17 16
#define DEC_18 17
#define DEC_19 18
#define DEC_20 19
#define DEC_21 20
#define DEC_22 21
#define DEC_23 22
#define DEC_24 23
#define DEC_25 24
#define DEC_26 25
#define DEC_27 26
#define DEC_28 27
#define DEC_29 28
#define DEC_30 29
#define DEC_31 30
#define DEC_32 31

#define DEC(N) CONCAT(DEC_, N)

#define SECOND_ARG(_, val, ...) val
#define SOME_CHECK_0 ~, 0
#define GET_SECOND_ARG(...) SECOND_ARG(__VA_ARGS__, SOME,)
#define SOME_OR_0(N) GET_SECOND_ARG(CONCAT(SOME_CHECK_, N))

#define EMPTY(...)
#define DEFER(...) __VA_ARGS__ EMPTY()

#define REPEAT_NAME_0() REPEAT_0
#define REPEAT_NAME_SOME() REPEAT_SOME
#define REPEAT_0(...)
#define REPEAT_SOME(N, stuff) DEFER(CONCAT(REPEAT_NAME_, SOME_OR_0(DEC(N))))()(DEC(N), stuff) stuff
#define REPEAT(N, stuff) EVAL(REPEAT_SOME(N, stuff))

#define REPEATM_NAME_0() REPEATM_0
#define REPEATM_NAME_SOME() REPEATM_SOME
#define REPEATM_0(...)
#define REPEATM_SOME(N, macro) macro(N) \
    DEFER(CONCAT(REPEATM_NAME_, SOME_OR_0(DEC(N))))()(DEC(N), macro)
#define REPEATM(N, macro) EVAL(REPEATM_SOME(N, macro))

#include "platform-specific.inc"

#if (uECC_WORD_SIZE == 1)
    #if uECC_SUPPORTS_secp160r1
        #define uECC_MAX_WORDS 21 /* Due to the size of curve_n. */
    #endif
    #if uECC_SUPPORTS_secp192r1
        #undef uECC_MAX_WORDS
        #define uECC_MAX_WORDS 24
    #endif
    #if uECC_SUPPORTS_secp224r1
        #undef uECC_MAX_WORDS
        #define uECC_MAX_WORDS 28
    #endif
    #if (uECC_SUPPORTS_secp256r1 || uECC_SUPPORTS_secp256k1)
        #undef uECC_MAX_WORDS
        #define uECC_MAX_WORDS 32
    #endif
#elif (uECC_WORD_SIZE == 4)
    #if uECC_SUPPORTS_secp160r1
        #define uECC_MAX_WORDS 6 /* Due to the size of curve_n. */
    #endif
    #if uECC_SUPPORTS_secp192r1
        #undef uECC_MAX_WORDS
        #define uECC_MAX_WORDS 6
    #endif
    #if uECC_SUPPORTS_secp224r1
        #undef uECC_MAX_WORDS
        #define uECC_MAX_WORDS 7
    #endif
    #if (uECC_SUPPORTS_secp256r1 || uECC_SUPPORTS_secp256k1)
        #undef uECC_MAX_WORDS
        #define uECC_MAX_WORDS 8
    #endif
#elif (uECC_WORD_SIZE == 8)
    #if uECC_SUPPORTS_secp160r1
        #define uECC_MAX_WORDS 3
    #endif
    #if uECC_SUPPORTS_secp192r1
        #undef uECC_MAX_WORDS
        #define uECC_MAX_WORDS 3
    #endif
    #if uECC_SUPPORTS_secp224r1
        #undef uECC_MAX_WORDS
        #define uECC_MAX_WORDS 4
    #endif
    #if (uECC_SUPPORTS_secp256r1 || uECC_SUPPORTS_secp256k1)
        #undef uECC_MAX_WORDS
        #define uECC_MAX_WORDS 4
    #endif
#endif /* uECC_WORD_SIZE */

#define BITS_TO_WORDS(num_bits) ((num_bits + ((uECC_WORD_SIZE * 8) - 1)) / (uECC_WORD_SIZE * 8))
#define BITS_TO_BYTES(num_bits) ((num_bits + 7) / 8)

struct uECC_Curve_t {
    wordcount_t num_words;
    wordcount_t num_bytes;
    bitcount_t num_n_bits;
    uECC_word_t p[uECC_MAX_WORDS];
    uECC_word_t n[uECC_MAX_WORDS];
    uECC_word_t G[uECC_MAX_WORDS * 2];
    uECC_word_t b[uECC_MAX_WORDS];
    void (*double_jacobian)(uECC_word_t * X1,
                            uECC_word_t * Y1,
                            uECC_word_t * Z1,
                            uECC_Curve curve);
#if uECC_SUPPORT_COMPRESSED_POINT
    void (*mod_sqrt)(uECC_word_t *a, uECC_Curve curve);
#endif
    void (*x_side)(uECC_word_t *result, const uECC_word_t *x, uECC_Curve curve);
#if (uECC_OPTIMIZATION_LEVEL > 0)
    void (*mmod_fast)(uECC_word_t *result, uECC_word_t *product);
#endif
};

#if uECC_VLI_NATIVE_LITTLE_ENDIAN
static void bcopy(uint8_t *dst,
                  const uint8_t *src,
                  unsigned num_bytes) {
    while (0 != num_bytes) {
        num_bytes--;
        dst[num_bytes] = src[num_bytes];
    }
}
#endif

static cmpresult_t uECC_vli_cmp_unsafe(const uECC_word_t *left,
                                       const uECC_word_t *right,
                                       wordcount_t num_words);

#if (uECC_PLATFORM == uECC_arm || uECC_PLATFORM == uECC_arm_thumb || \
        uECC_PLATFORM == uECC_arm_thumb2)
    #include "asm_arm.inc"
#endif

#if (uECC_PLATFORM == uECC_avr)
    #include "asm_avr.inc"
#endif

#if default_RNG_defined
static uECC_RNG_Function g_rng_function = &default_RNG;
#else
static uECC_RNG_Function g_rng_function = 0;
#endif

void uECC_set_rng(uECC_RNG_Function rng_function) {
    g_rng_function = rng_function;
}

uECC_RNG_Function uECC_get_rng(void) {
    return g_rng_function;
}

int uECC_curve_private_key_size(uECC_Curve curve) {
    return BITS_TO_BYTES(curve->num_n_bits);
}

int uECC_curve_public_key_size(uECC_Curve curve) {
    return 2 * curve->num_bytes;
}

#if !asm_clear
uECC_VLI_API void uECC_vli_clear(uECC_word_t *vli, wordcount_t num_words) {
    wordcount_t i;
    for (i = 0; i < num_words; ++i) {
        vli[i] = 0;
    }
}
#endif /* !asm_clear */

/* Constant-time comparison to zero - secure way to compare long integers */
/* Returns 1 if vli == 0, 0 otherwise. */
uECC_VLI_API uECC_word_t uECC_vli_isZero(const uECC_word_t *vli, wordcount_t num_words) {
    uECC_word_t bits = 0;
    wordcount_t i;
    for (i = 0; i < num_words; ++i) {
        bits |= vli[i];
    }
    return (bits == 0);
}

/* Returns nonzero if bit 'bit' of vli is set. */
uECC_VLI_API uECC_word_t uECC_vli_testBit(const uECC_word_t *vli, bitcount_t bit) {
    return (vli[bit >> uECC_WORD_BITS_SHIFT] & ((uECC_word_t)1 << (bit & uECC_WORD_BITS_MASK)));
}

/* Counts the number of words in vli. */
static wordcount_t vli_numDigits(const uECC_word_t *vli, const wordcount_t max_words) {
    wordcount_t i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for (i = max_words - 1; i >= 0 && vli[i] == 0; --i) {
    }

    return (i + 1);
}

/* Counts the number of bits required to represent vli. */
uECC_VLI_API bitcount_t uECC_vli_numBits(const uECC_word_t *vli, const wordcount_t max_words) {
    uECC_word_t i;
    uECC_word_t digit;

    wordcount_t num_digits = vli_numDigits(vli, max_words);
    if (num_digits == 0) {
        return 0;
    }

    digit = vli[num_digits - 1];
    for (i = 0; digit; ++i) {
        digit >>= 1;
    }

    return (((bitcount_t)(num_digits - 1) << uECC_WORD_BITS_SHIFT) + i);
}

/* Sets dest = src. */
#if !asm_set
uECC_VLI_API void uECC_vli_set(uECC_word_t *dest, const uECC_word_t *src, wordcount_t num_words) {
    wordcount_t i;
    for (i = 0; i < num_words; ++i) {
        dest[i] = src[i];
    }
}
#endif /* !asm_set */

/* Returns sign of left - right. */
static cmpresult_t uECC_vli_cmp_unsafe(const uECC_word_t *left,
                                       const uECC_word_t *right,
                                       wordcount_t num_words) {
    wordcount_t i;
    for (i = num_words - 1; i >= 0; --i) {
        if (left[i] > right[i]) {
            return 1;
        } else if (left[i] < right[i]) {
            return -1;
        }
    }
    return 0;
}

/* Constant-time comparison function - secure way to compare long integers */
/* Returns one if left == right, zero otherwise. */
uECC_VLI_API uECC_word_t uECC_vli_equal(const uECC_word_t *left,
                                        const uECC_word_t *right,
                                        wordcount_t num_words) {
    uECC_word_t diff = 0;
    wordcount_t i;
    for (i = num_words - 1; i >= 0; --i) {
        diff |= (left[i] ^ right[i]);
    }
    return (diff == 0);
}

uECC_VLI_API uECC_word_t uECC_vli_sub(uECC_word_t *result,
                                      const uECC_word_t *left,
                                      const uECC_word_t *right,
                                      wordcount_t num_words);

/* Returns sign of left - right, in constant time. */
uECC_VLI_API cmpresult_t uECC_vli_cmp(const uECC_word_t *left,
                                      const uECC_word_t *right,
                                      wordcount_t num_words) {
    uECC_word_t tmp[uECC_MAX_WORDS];
    uECC_word_t neg = !!uECC_vli_sub(tmp, left, right, num_words);
    uECC_word_t equal = uECC_vli_isZero(tmp, num_words);
    return (!equal - 2 * neg);
}

/* Computes vli = vli >> 1. */
#if !asm_rshift1
uECC_VLI_API void uECC_vli_rshift1(uECC_word_t *vli, wordcount_t num_words) {
    uECC_word_t *end = vli;
    uECC_word_t carry = 0;

    vli += num_words;
    while (vli-- > end) {
        uECC_word_t temp = *vli;
        *vli = (temp >> 1) | carry;
        carry = temp << (uECC_WORD_BITS - 1);
    }
}
#endif /* !asm_rshift1 */

/* Computes result = left + right, returning carry. Can modify in place. */
#if !asm_add
uECC_VLI_API uECC_word_t uECC_vli_add(uECC_word_t *result,
                                      const uECC_word_t *left,
                                      const uECC_word_t *right,
                                      wordcount_t num_words) {
    uECC_word_t carry = 0;
    wordcount_t i;
    for (i = 0; i < num_words; ++i) {
        uECC_word_t sum = left[i] + right[i] + carry;
        if (sum != left[i]) {
            carry = (sum < left[i]);
        }
        result[i] = sum;
    }
    return carry;
}
#endif /* !asm_add */

/* Computes result = left - right, returning borrow. Can modify in place. */
#if !asm_sub
uECC_VLI_API uECC_word_t uECC_vli_sub(uECC_word_t *result,
                                      const uECC_word_t *left,
                                      const uECC_word_t *right,
                                      wordcount_t num_words) {
    uECC_word_t borrow = 0;
    wordcount_t i;
    for (i = 0; i < num_words; ++i) {
        uECC_word_t diff = left[i] - right[i] - borrow;
        if (diff != left[i]) {
            borrow = (diff > left[i]);
        }
        result[i] = diff;
    }
    return borrow;
}
#endif /* !asm_sub */

#if !asm_mult || (uECC_SQUARE_FUNC && !asm_square) || \
    (uECC_SUPPORTS_secp256k1 && (uECC_OPTIMIZATION_LEVEL > 0) && \
        ((uECC_WORD_SIZE == 1) || (uECC_WORD_SIZE == 8)))
static void muladd(uECC_word_t a,
                   uECC_word_t b,
                   uECC_word_t *r0,
                   uECC_word_t *r1,
                   uECC_word_t *r2) {
#if uECC_WORD_SIZE == 8 && !SUPPORTS_INT128
    uint64_t a0 = a & 0xffffffffull;
    uint64_t a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull;
    uint64_t b1 = b >> 32;

    uint64_t i0 = a0 * b0;
    uint64_t i1 = a0 * b1;
    uint64_t i2 = a1 * b0;
    uint64_t i3 = a1 * b1;

    uint64_t p0, p1;

    i2 += (i0 >> 32);
    i2 += i1;
    if (i2 < i1) { /* overflow */
        i3 += 0x100000000ull;
    }

    p0 = (i0 & 0xffffffffull) | (i2 << 32);
    p1 = i3 + (i2 >> 32);

    *r0 += p0;
    *r1 += (p1 + (*r0 < p0));
    *r2 += ((*r1 < p1) || (*r1 == p1 && *r0 < p0));
#else
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
#endif
}
#endif /* muladd needed */

#if !asm_mult
uECC_VLI_API void uECC_vli_mult(uECC_word_t *result,
                                const uECC_word_t *left,
                                const uECC_word_t *right,
                                wordcount_t num_words) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;
    wordcount_t i, k;

    /* Compute each digit of result in sequence, maintaining the carries. */
    for (k = 0; k < num_words; ++k) {
        for (i = 0; i <= k; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    for (k = num_words; k < num_words * 2 - 1; ++k) {
        for (i = (k + 1) - num_words; i < num_words; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    result[num_words * 2 - 1] = r0;
}
#endif /* !asm_mult */

#if uECC_SQUARE_FUNC

#if !asm_square
static void mul2add(uECC_word_t a,
                    uECC_word_t b,
                    uECC_word_t *r0,
                    uECC_word_t *r1,
                    uECC_word_t *r2) {
#if uECC_WORD_SIZE == 8 && !SUPPORTS_INT128
    uint64_t a0 = a & 0xffffffffull;
    uint64_t a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull;
    uint64_t b1 = b >> 32;

    uint64_t i0 = a0 * b0;
    uint64_t i1 = a0 * b1;
    uint64_t i2 = a1 * b0;
    uint64_t i3 = a1 * b1;

    uint64_t p0, p1;

    i2 += (i0 >> 32);
    i2 += i1;
    if (i2 < i1)
    { /* overflow */
        i3 += 0x100000000ull;
    }

    p0 = (i0 & 0xffffffffull) | (i2 << 32);
    p1 = i3 + (i2 >> 32);

    *r2 += (p1 >> 63);
    p1 = (p1 << 1) | (p0 >> 63);
    p0 <<= 1;

    *r0 += p0;
    *r1 += (p1 + (*r0 < p0));
    *r2 += ((*r1 < p1) || (*r1 == p1 && *r0 < p0));
#else
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    *r2 += (p >> (uECC_WORD_BITS * 2 - 1));
    p *= 2;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
#endif
}

uECC_VLI_API void uECC_vli_square(uECC_word_t *result,
                                  const uECC_word_t *left,
                                  wordcount_t num_words) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;

    wordcount_t i, k;

    for (k = 0; k < num_words * 2 - 1; ++k) {
        uECC_word_t min = (k < num_words ? 0 : (k + 1) - num_words);
        for (i = min; i <= k && i <= k - i; ++i) {
            if (i < k-i) {
                mul2add(left[i], left[k - i], &r0, &r1, &r2);
            } else {
                muladd(left[i], left[k - i], &r0, &r1, &r2);
            }
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }

    result[num_words * 2 - 1] = r0;
}
#endif /* !asm_square */

#else /* uECC_SQUARE_FUNC */

#if uECC_ENABLE_VLI_API
uECC_VLI_API void uECC_vli_square(uECC_word_t *result,
                                  const uECC_word_t *left,
                                  wordcount_t num_words) {
    uECC_vli_mult(result, left, left, num_words);
}
#endif /* uECC_ENABLE_VLI_API */

#endif /* uECC_SQUARE_FUNC */

/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
uECC_VLI_API void uECC_vli_modAdd(uECC_word_t *result,
                                  const uECC_word_t *left,
                                  const uECC_word_t *right,
                                  const uECC_word_t *mod,
                                  wordcount_t num_words) {
    uECC_word_t carry = uECC_vli_add(result, left, right, num_words);
    if (carry || uECC_vli_cmp_unsafe(mod, result, num_words) != 1) {
        /* result > mod (result = mod + remainder), so subtract mod to get remainder. */
        uECC_vli_sub(result, result, mod, num_words);
    }
}

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
uECC_VLI_API void uECC_vli_modSub(uECC_word_t *result,
                                  const uECC_word_t *left,
                                  const uECC_word_t *right,
                                  const uECC_word_t *mod,
                                  wordcount_t num_words) {
    uECC_word_t l_borrow = uECC_vli_sub(result, left, right, num_words);
    if (l_borrow) {
        /* In this case, result == -diff == (max int) - diff. Since -x % d == d - x,
           we can get the correct result from result + mod (with overflow). */
        uECC_vli_add(result, result, mod, num_words);
    }
}

/* Computes result = product % mod, where product is 2N words long. */
/* Currently only designed to work for curve_p or curve_n. */
uECC_VLI_API void uECC_vli_mmod(uECC_word_t *result,
                                uECC_word_t *product,
                                const uECC_word_t *mod,
                                wordcount_t num_words) {
    uECC_word_t mod_multiple[2 * uECC_MAX_WORDS];
    uECC_word_t tmp[2 * uECC_MAX_WORDS];
    uECC_word_t *v[2] = {tmp, product};
    uECC_word_t index;

    /* Shift mod so its highest set bit is at the maximum position. */
    bitcount_t shift = (num_words * 2 * uECC_WORD_BITS) - uECC_vli_numBits(mod, num_words);
    wordcount_t word_shift = shift / uECC_WORD_BITS;
    wordcount_t bit_shift = shift % uECC_WORD_BITS;
    uECC_word_t carry = 0;
    uECC_vli_clear(mod_multiple, word_shift);
    if (bit_shift > 0) {
        for(index = 0; index < (uECC_word_t)num_words; ++index) {
            mod_multiple[word_shift + index] = (mod[index] << bit_shift) | carry;
            carry = mod[index] >> (uECC_WORD_BITS - bit_shift);
        }
    } else {
        uECC_vli_set(mod_multiple + word_shift, mod, num_words);
    }

    for (index = 1; shift >= 0; --shift) {
        uECC_word_t borrow = 0;
        wordcount_t i;
        for (i = 0; i < num_words * 2; ++i) {
            uECC_word_t diff = v[index][i] - mod_multiple[i] - borrow;
            if (diff != v[index][i]) {
                borrow = (diff > v[index][i]);
            }
            v[1 - index][i] = diff;
        }
        index = !(index ^ borrow); /* Swap the index if there was no borrow */
        uECC_vli_rshift1(mod_multiple, num_words);
        mod_multiple[num_words - 1] |= mod_multiple[num_words] << (uECC_WORD_BITS - 1);
        uECC_vli_rshift1(mod_multiple + num_words, num_words);
    }
    uECC_vli_set(result, v[index], num_words);
}

/* Computes result = (left * right) % mod. */
uECC_VLI_API void uECC_vli_modMult(uECC_word_t *result,
                                   const uECC_word_t *left,
                                   const uECC_word_t *right,
                                   const uECC_word_t *mod,
                                   wordcount_t num_words) {
    uECC_word_t product[2 * uECC_MAX_WORDS];
    uECC_vli_mult(product, left, right, num_words);
    uECC_vli_mmod(result, product, mod, num_words);
}

uECC_VLI_API void uECC_vli_modMult_fast(uECC_word_t *result,
                                        const uECC_word_t *left,
                                        const uECC_word_t *right,
                                        uECC_Curve curve) {
    uECC_word_t product[2 * uECC_MAX_WORDS];
    uECC_vli_mult(product, left, right, curve->num_words);
#if (uECC_OPTIMIZATION_LEVEL > 0)
    curve->mmod_fast(result, product);
#else
    uECC_vli_mmod(result, product, curve->p, curve->num_words);
#endif
}

#if uECC_SQUARE_FUNC

#if uECC_ENABLE_VLI_API
/* Computes result = left^2 % mod. */
uECC_VLI_API void uECC_vli_modSquare(uECC_word_t *result,
                                     const uECC_word_t *left,
                                     const uECC_word_t *mod,
                                     wordcount_t num_words) {
    uECC_word_t product[2 * uECC_MAX_WORDS];
    uECC_vli_square(product, left, num_words);
    uECC_vli_mmod(result, product, mod, num_words);
}
#endif /* uECC_ENABLE_VLI_API */

uECC_VLI_API void uECC_vli_modSquare_fast(uECC_word_t *result,
                                          const uECC_word_t *left,
                                          uECC_Curve curve) {
    uECC_word_t product[2 * uECC_MAX_WORDS];
    uECC_vli_square(product, left, curve->num_words);
#if (uECC_OPTIMIZATION_LEVEL > 0)
    curve->mmod_fast(result, product);
#else
    uECC_vli_mmod(result, product, curve->p, curve->num_words);
#endif
}

#else /* uECC_SQUARE_FUNC */

#if uECC_ENABLE_VLI_API
uECC_VLI_API void uECC_vli_modSquare(uECC_word_t *result,
                                     const uECC_word_t *left,
                                     const uECC_word_t *mod,
                                     wordcount_t num_words) {
    uECC_vli_modMult(result, left, left, mod, num_words);
}
#endif /* uECC_ENABLE_VLI_API */

uECC_VLI_API void uECC_vli_modSquare_fast(uECC_word_t *result,
                                          const uECC_word_t *left,
                                          uECC_Curve curve) {
    uECC_vli_modMult_fast(result, left, left, curve);
}

#endif /* uECC_SQUARE_FUNC */

#define EVEN(vli) (!(vli[0] & 1))
static void vli_modInv_update(uECC_word_t *uv,
                              const uECC_word_t *mod,
                              wordcount_t num_words) {
    uECC_word_t carry = 0;
    if (!EVEN(uv)) {
        carry = uECC_vli_add(uv, uv, mod, num_words);
    }
    uECC_vli_rshift1(uv, num_words);
    if (carry) {
        uv[num_words - 1] |= HIGH_BIT_SET;
    }
}

/* Computes result = (1 / input) % mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide" */
uECC_VLI_API void uECC_vli_modInv(uECC_word_t *result,
                                  const uECC_word_t *input,
                                  const uECC_word_t *mod,
                                  wordcount_t num_words) {
    uECC_word_t a[uECC_MAX_WORDS], b[uECC_MAX_WORDS], u[uECC_MAX_WORDS], v[uECC_MAX_WORDS];
    cmpresult_t cmpResult;

    if (uECC_vli_isZero(input, num_words)) {
        uECC_vli_clear(result, num_words);
        return;
    }

    uECC_vli_set(a, input, num_words);
    uECC_vli_set(b, mod, num_words);
    uECC_vli_clear(u, num_words);
    u[0] = 1;
    uECC_vli_clear(v, num_words);
    while ((cmpResult = uECC_vli_cmp_unsafe(a, b, num_words)) != 0) {
        if (EVEN(a)) {
            uECC_vli_rshift1(a, num_words);
            vli_modInv_update(u, mod, num_words);
        } else if (EVEN(b)) {
            uECC_vli_rshift1(b, num_words);
            vli_modInv_update(v, mod, num_words);
        } else if (cmpResult > 0) {
            uECC_vli_sub(a, a, b, num_words);
            uECC_vli_rshift1(a, num_words);
            if (uECC_vli_cmp_unsafe(u, v, num_words) < 0) {
                uECC_vli_add(u, u, mod, num_words);
            }
            uECC_vli_sub(u, u, v, num_words);
            vli_modInv_update(u, mod, num_words);
        } else {
            uECC_vli_sub(b, b, a, num_words);
            uECC_vli_rshift1(b, num_words);
            if (uECC_vli_cmp_unsafe(v, u, num_words) < 0) {
                uECC_vli_add(v, v, mod, num_words);
            }
            uECC_vli_sub(v, v, u, num_words);
            vli_modInv_update(v, mod, num_words);
        }
    }
    uECC_vli_set(result, u, num_words);
}

/* ------ Point operations ------ */

#include "curve-specific.inc"

/* Returns 1 if 'point' is the point at infinity, 0 otherwise. */
#define EccPoint_isZero(point, curve) uECC_vli_isZero((point), (curve)->num_words * 2)

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
From http://eprint.iacr.org/2011/338.pdf
*/

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(uECC_word_t * X1,
                    uECC_word_t * Y1,
                    const uECC_word_t * const Z,
                    uECC_Curve curve) {
    uECC_word_t t1[uECC_MAX_WORDS];

    uECC_vli_modSquare_fast(t1, Z, curve);    /* z^2 */
    uECC_vli_modMult_fast(X1, X1, t1, curve); /* x1 * z^2 */
    uECC_vli_modMult_fast(t1, t1, Z, curve);  /* z^3 */
    uECC_vli_modMult_fast(Y1, Y1, t1, curve); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void XYcZ_initial_double(uECC_word_t * X1,
                                uECC_word_t * Y1,
                                uECC_word_t * X2,
                                uECC_word_t * Y2,
                                const uECC_word_t * const initial_Z,
                                uECC_Curve curve) {
    uECC_word_t z[uECC_MAX_WORDS];
    wordcount_t num_words = curve->num_words;
    if (initial_Z) {
        uECC_vli_set(z, initial_Z, num_words);
    } else {
        uECC_vli_clear(z, num_words);
        z[0] = 1;
    }

    uECC_vli_set(X2, X1, num_words);
    uECC_vli_set(Y2, Y1, num_words);

    apply_z(X1, Y1, z, curve);
    curve->double_jacobian(X1, Y1, z, curve);
    apply_z(X2, Y2, z, curve);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
*/
static void XYcZ_add(uECC_word_t * X1,
                     uECC_word_t * Y1,
                     uECC_word_t * X2,
                     uECC_word_t * Y2,
                     uECC_Curve curve) {
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uECC_word_t t5[uECC_MAX_WORDS];
    wordcount_t num_words = curve->num_words;

    uECC_vli_modSub(t5, X2, X1, curve->p, num_words); /* t5 = x2 - x1 */
    uECC_vli_modSquare_fast(t5, t5, curve);                  /* t5 = (x2 - x1)^2 = A */
    uECC_vli_modMult_fast(X1, X1, t5, curve);                /* t1 = x1*A = B */
    uECC_vli_modMult_fast(X2, X2, t5, curve);                /* t3 = x2*A = C */
    uECC_vli_modSub(Y2, Y2, Y1, curve->p, num_words); /* t4 = y2 - y1 */
    uECC_vli_modSquare_fast(t5, Y2, curve);                  /* t5 = (y2 - y1)^2 = D */

    uECC_vli_modSub(t5, t5, X1, curve->p, num_words); /* t5 = D - B */
    uECC_vli_modSub(t5, t5, X2, curve->p, num_words); /* t5 = D - B - C = x3 */
    uECC_vli_modSub(X2, X2, X1, curve->p, num_words); /* t3 = C - B */
    uECC_vli_modMult_fast(Y1, Y1, X2, curve);                /* t2 = y1*(C - B) */
    uECC_vli_modSub(X2, X1, t5, curve->p, num_words); /* t3 = B - x3 */
    uECC_vli_modMult_fast(Y2, Y2, X2, curve);                /* t4 = (y2 - y1)*(B - x3) */
    uECC_vli_modSub(Y2, Y2, Y1, curve->p, num_words); /* t4 = y3 */

    uECC_vli_set(X2, t5, num_words);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
static void XYcZ_addC(uECC_word_t * X1,
                      uECC_word_t * Y1,
                      uECC_word_t * X2,
                      uECC_word_t * Y2,
                      uECC_Curve curve) {
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uECC_word_t t5[uECC_MAX_WORDS];
    uECC_word_t t6[uECC_MAX_WORDS];
    uECC_word_t t7[uECC_MAX_WORDS];
    wordcount_t num_words = curve->num_words;

    uECC_vli_modSub(t5, X2, X1, curve->p, num_words); /* t5 = x2 - x1 */
    uECC_vli_modSquare_fast(t5, t5, curve);                  /* t5 = (x2 - x1)^2 = A */
    uECC_vli_modMult_fast(X1, X1, t5, curve);                /* t1 = x1*A = B */
    uECC_vli_modMult_fast(X2, X2, t5, curve);                /* t3 = x2*A = C */
    uECC_vli_modAdd(t5, Y2, Y1, curve->p, num_words); /* t5 = y2 + y1 */
    uECC_vli_modSub(Y2, Y2, Y1, curve->p, num_words); /* t4 = y2 - y1 */

    uECC_vli_modSub(t6, X2, X1, curve->p, num_words); /* t6 = C - B */
    uECC_vli_modMult_fast(Y1, Y1, t6, curve);                /* t2 = y1 * (C - B) = E */
    uECC_vli_modAdd(t6, X1, X2, curve->p, num_words); /* t6 = B + C */
    uECC_vli_modSquare_fast(X2, Y2, curve);                  /* t3 = (y2 - y1)^2 = D */
    uECC_vli_modSub(X2, X2, t6, curve->p, num_words); /* t3 = D - (B + C) = x3 */

    uECC_vli_modSub(t7, X1, X2, curve->p, num_words); /* t7 = B - x3 */
    uECC_vli_modMult_fast(Y2, Y2, t7, curve);                /* t4 = (y2 - y1)*(B - x3) */
    uECC_vli_modSub(Y2, Y2, Y1, curve->p, num_words); /* t4 = (y2 - y1)*(B - x3) - E = y3 */

    uECC_vli_modSquare_fast(t7, t5, curve);                  /* t7 = (y2 + y1)^2 = F */
    uECC_vli_modSub(t7, t7, t6, curve->p, num_words); /* t7 = F - (B + C) = x3' */
    uECC_vli_modSub(t6, t7, X1, curve->p, num_words); /* t6 = x3' - B */
    uECC_vli_modMult_fast(t6, t6, t5, curve);                /* t6 = (y2+y1)*(x3' - B) */
    uECC_vli_modSub(Y1, t6, Y1, curve->p, num_words); /* t2 = (y2+y1)*(x3' - B) - E = y3' */

    uECC_vli_set(X1, t7, num_words);
}

/* result may overlap point. */
static void EccPoint_mult(uECC_word_t * result,
                          const uECC_word_t * point,
                          const uECC_word_t * scalar,
                          const uECC_word_t * initial_Z,
                          bitcount_t num_bits,
                          uECC_Curve curve) {
    /* R0 and R1 */
    uECC_word_t Rx[2][uECC_MAX_WORDS];
    uECC_word_t Ry[2][uECC_MAX_WORDS];
    uECC_word_t z[uECC_MAX_WORDS];
    bitcount_t i;
    uECC_word_t nb;
    wordcount_t num_words = curve->num_words;

    uECC_vli_set(Rx[1], point, num_words);
    uECC_vli_set(Ry[1], point + num_words, num_words);

    XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], initial_Z, curve);

    for (i = num_bits - 2; i > 0; --i) {
        nb = !uECC_vli_testBit(scalar, i);
        XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb], curve);
        XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb], curve);
    }

    nb = !uECC_vli_testBit(scalar, 0);
    XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb], curve);

    /* Find final 1/Z value. */
    uECC_vli_modSub(z, Rx[1], Rx[0], curve->p, num_words); /* X1 - X0 */
    uECC_vli_modMult_fast(z, z, Ry[1 - nb], curve);               /* Yb * (X1 - X0) */
    uECC_vli_modMult_fast(z, z, point, curve);                    /* xP * Yb * (X1 - X0) */
    uECC_vli_modInv(z, z, curve->p, num_words);            /* 1 / (xP * Yb * (X1 - X0)) */
    /* yP / (xP * Yb * (X1 - X0)) */
    uECC_vli_modMult_fast(z, z, point + num_words, curve);
    uECC_vli_modMult_fast(z, z, Rx[1 - nb], curve); /* Xb * yP / (xP * Yb * (X1 - X0)) */
    /* End 1/Z calculation */

    XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb], curve);
    apply_z(Rx[0], Ry[0], z, curve);

    uECC_vli_set(result, Rx[0], num_words);
    uECC_vli_set(result + num_words, Ry[0], num_words);
}

static uECC_word_t regularize_k(const uECC_word_t * const k,
                                uECC_word_t *k0,
                                uECC_word_t *k1,
                                uECC_Curve curve) {
    wordcount_t num_n_words = BITS_TO_WORDS(curve->num_n_bits);
    bitcount_t num_n_bits = curve->num_n_bits;
    uECC_word_t carry = uECC_vli_add(k0, k, curve->n, num_n_words) ||
        (num_n_bits < ((bitcount_t)num_n_words * uECC_WORD_SIZE * 8) &&
         uECC_vli_testBit(k0, num_n_bits));
    uECC_vli_add(k1, k0, curve->n, num_n_words);
    return carry;
}

static uECC_word_t EccPoint_compute_public_key(uECC_word_t *result,
                                               uECC_word_t *private,
                                               uECC_Curve curve) {
    uECC_word_t tmp1[uECC_MAX_WORDS];
    uECC_word_t tmp2[uECC_MAX_WORDS];
    uECC_word_t *p2[2] = {tmp1, tmp2};
    uECC_word_t carry;

    /* Regularize the bitcount for the private key so that attackers cannot use a side channel
       attack to learn the number of leading zeros. */
    carry = regularize_k(private, tmp1, tmp2, curve);

    EccPoint_mult(result, curve->G, p2[!carry], 0, curve->num_n_bits + 1, curve);

    if (EccPoint_isZero(result, curve)) {
        return 0;
    }
    return 1;
}

#if uECC_WORD_SIZE == 1

uECC_VLI_API void uECC_vli_nativeToBytes(uint8_t *bytes,
                                         int num_bytes,
                                         const uint8_t *native) {
    wordcount_t i;
    for (i = 0; i < num_bytes; ++i) {
        bytes[i] = native[(num_bytes - 1) - i];
    }
}

uECC_VLI_API void uECC_vli_bytesToNative(uint8_t *native,
                                         const uint8_t *bytes,
                                         int num_bytes) {
    uECC_vli_nativeToBytes(native, num_bytes, bytes);
}

#else

uECC_VLI_API void uECC_vli_nativeToBytes(uint8_t *bytes,
                                         int num_bytes,
                                         const uECC_word_t *native) {
    wordcount_t i;
    for (i = 0; i < num_bytes; ++i) {
        unsigned b = num_bytes - 1 - i;
        bytes[i] = native[b / uECC_WORD_SIZE] >> (8 * (b % uECC_WORD_SIZE));
    }
}

uECC_VLI_API void uECC_vli_bytesToNative(uECC_word_t *native,
                                         const uint8_t *bytes,
                                         int num_bytes) {
    wordcount_t i;
    uECC_vli_clear(native, (num_bytes + (uECC_WORD_SIZE - 1)) / uECC_WORD_SIZE);
    for (i = 0; i < num_bytes; ++i) {
        unsigned b = num_bytes - 1 - i;
        native[b / uECC_WORD_SIZE] |=
            (uECC_word_t)bytes[i] << (8 * (b % uECC_WORD_SIZE));
    }
}

#endif /* uECC_WORD_SIZE */

/* Generates a random integer in the range 0 < random < top.
   Both random and top have num_words words. */
uECC_VLI_API int uECC_generate_random_int(uECC_word_t *random,
                                          const uECC_word_t *top,
                                          wordcount_t num_words) {
    uECC_word_t mask = (uECC_word_t)-1;
    uECC_word_t tries;
    bitcount_t num_bits = uECC_vli_numBits(top, num_words);

    if (!g_rng_function) {
        return 0;
    }

    for (tries = 0; tries < uECC_RNG_MAX_TRIES; ++tries) {
        if (!g_rng_function((uint8_t *)random, num_words * uECC_WORD_SIZE)) {
            return 0;
	    }
        random[num_words - 1] &= mask >> ((bitcount_t)(num_words * uECC_WORD_SIZE * 8 - num_bits));
        if (!uECC_vli_isZero(random, num_words) &&
		        uECC_vli_cmp(top, random, num_words) == 1) {
            return 1;
        }
    }
    return 0;
}

int uECC_make_key(uint8_t *public_key,
                  uint8_t *private_key,
                  uECC_Curve curve) {
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *private = (uECC_word_t *)private_key;
    uECC_word_t *public = (uECC_word_t *)public_key;
#else
    uECC_word_t private[uECC_MAX_WORDS];
    uECC_word_t public[uECC_MAX_WORDS * 2];
#endif
    uECC_word_t tries;

    for (tries = 0; tries < uECC_RNG_MAX_TRIES; ++tries) {
        if (!uECC_generate_random_int(private, curve->n, BITS_TO_WORDS(curve->num_n_bits))) {
            return 0;
        }

        if (EccPoint_compute_public_key(public, private, curve)) {
#if uECC_VLI_NATIVE_LITTLE_ENDIAN == 0
            uECC_vli_nativeToBytes(private_key, BITS_TO_BYTES(curve->num_n_bits), private);
            uECC_vli_nativeToBytes(public_key, curve->num_bytes, public);
            uECC_vli_nativeToBytes(
                public_key + curve->num_bytes, curve->num_bytes, public + curve->num_words);
#endif
            return 1;
        }
    }
    return 0;
}

int uECC_shared_secret(const uint8_t *public_key,
                       const uint8_t *private_key,
                       uint8_t *secret,
                       uECC_Curve curve) {
    uECC_word_t public[uECC_MAX_WORDS * 2];
    uECC_word_t private[uECC_MAX_WORDS];

    uECC_word_t tmp[uECC_MAX_WORDS];
    uECC_word_t *p2[2] = {private, tmp};
    uECC_word_t *initial_Z = 0;
    uECC_word_t carry;
    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) private, private_key, num_bytes);
    bcopy((uint8_t *) public, public_key, num_bytes*2);
#else
    uECC_vli_bytesToNative(private, private_key, BITS_TO_BYTES(curve->num_n_bits));
    uECC_vli_bytesToNative(public, public_key, num_bytes);
    uECC_vli_bytesToNative(public + num_words, public_key + num_bytes, num_bytes);
#endif

    /* Regularize the bitcount for the private key so that attackers cannot use a side channel
       attack to learn the number of leading zeros. */
    carry = regularize_k(private, private, tmp, curve);

    /* If an RNG function was specified, try to get a random initial Z value to improve
       protection against side-channel attacks. */
    if (g_rng_function) {
        if (!uECC_generate_random_int(p2[carry], curve->p, num_words)) {
            return 0;
        }
        initial_Z = p2[carry];
    }

    EccPoint_mult(public, public, p2[!carry], initial_Z, curve->num_n_bits + 1, curve);
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) secret, (uint8_t *) public, num_bytes);
#else
    uECC_vli_nativeToBytes(secret, num_bytes, public);
#endif
    return !EccPoint_isZero(public, curve);
}

#if uECC_SUPPORT_COMPRESSED_POINT
void uECC_compress(const uint8_t *public_key, uint8_t *compressed, uECC_Curve curve) {
    wordcount_t i;
    for (i = 0; i < curve->num_bytes; ++i) {
        compressed[i+1] = public_key[i];
    }
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    compressed[0] = 2 + (public_key[curve->num_bytes] & 0x01);
#else
    compressed[0] = 2 + (public_key[curve->num_bytes * 2 - 1] & 0x01);
#endif
}

void uECC_decompress(const uint8_t *compressed, uint8_t *public_key, uECC_Curve curve) {
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *point = (uECC_word_t *)public_key;
#else
    uECC_word_t point[uECC_MAX_WORDS * 2];
#endif
    uECC_word_t *y = point + curve->num_words;
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy(public_key, compressed+1, curve->num_bytes);
#else
    uECC_vli_bytesToNative(point, compressed + 1, curve->num_bytes);
#endif
    curve->x_side(y, point, curve);
    curve->mod_sqrt(y, curve);

    if ((y[0] & 0x01) != (compressed[0] & 0x01)) {
        uECC_vli_sub(y, curve->p, y, curve->num_words);
    }

#if uECC_VLI_NATIVE_LITTLE_ENDIAN == 0
    uECC_vli_nativeToBytes(public_key, curve->num_bytes, point);
    uECC_vli_nativeToBytes(public_key + curve->num_bytes, curve->num_bytes, y);
#endif
}
#endif /* uECC_SUPPORT_COMPRESSED_POINT */

int uECC_valid_point(const uECC_word_t *point, uECC_Curve curve) {
    uECC_word_t tmp1[uECC_MAX_WORDS];
    uECC_word_t tmp2[uECC_MAX_WORDS];
    wordcount_t num_words = curve->num_words;

    /* The point at infinity is invalid. */
    if (EccPoint_isZero(point, curve)) {
        return 0;
    }

    /* x and y must be smaller than p. */
    if (uECC_vli_cmp_unsafe(curve->p, point, num_words) != 1 ||
            uECC_vli_cmp_unsafe(curve->p, point + num_words, num_words) != 1) {
        return 0;
    }

    uECC_vli_modSquare_fast(tmp1, point + num_words, curve);
    curve->x_side(tmp2, point, curve); /* tmp2 = x^3 + ax + b */

    /* Make sure that y^2 == x^3 + ax + b */
    return (int)(uECC_vli_equal(tmp1, tmp2, num_words));
}

int uECC_valid_public_key(const uint8_t *public_key, uECC_Curve curve) {
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *public = (uECC_word_t *)public_key;
#else
    uECC_word_t public[uECC_MAX_WORDS * 2];
#endif

#if uECC_VLI_NATIVE_LITTLE_ENDIAN == 0
    uECC_vli_bytesToNative(public, public_key, curve->num_bytes);
    uECC_vli_bytesToNative(
        public + curve->num_words, public_key + curve->num_bytes, curve->num_bytes);
#endif
    return uECC_valid_point(public, curve);
}

int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve) {
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *private = (uECC_word_t *)private_key;
    uECC_word_t *public = (uECC_word_t *)public_key;
#else
    uECC_word_t private[uECC_MAX_WORDS];
    uECC_word_t public[uECC_MAX_WORDS * 2];
#endif

#if uECC_VLI_NATIVE_LITTLE_ENDIAN == 0
    uECC_vli_bytesToNative(private, private_key, BITS_TO_BYTES(curve->num_n_bits));
#endif

    /* Make sure the private key is in the range [1, n-1]. */
    if (uECC_vli_isZero(private, BITS_TO_WORDS(curve->num_n_bits))) {
        return 0;
    }

    if (uECC_vli_cmp(curve->n, private, BITS_TO_WORDS(curve->num_n_bits)) != 1) {
        return 0;
    }

    /* Compute public key. */
    if (!EccPoint_compute_public_key(public, private, curve)) {
        return 0;
    }

#if uECC_VLI_NATIVE_LITTLE_ENDIAN == 0
    uECC_vli_nativeToBytes(public_key, curve->num_bytes, public);
    uECC_vli_nativeToBytes(
        public_key + curve->num_bytes, curve->num_bytes, public + curve->num_words);
#endif
    return 1;
}


/* -------- ECDSA code -------- */

static void bits2int(uECC_word_t *native,
                     const uint8_t *bits,
                     unsigned bits_size,
                     uECC_Curve curve) {
    unsigned num_n_bytes = BITS_TO_BYTES(curve->num_n_bits);
    unsigned num_n_words = BITS_TO_WORDS(curve->num_n_bits);
    int shift;
    uECC_word_t carry;
    uECC_word_t *ptr;

    if (bits_size > num_n_bytes) {
        bits_size = num_n_bytes;
    }

    uECC_vli_clear(native, num_n_words);
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) native, bits, bits_size);
#else
    uECC_vli_bytesToNative(native, bits, bits_size);
#endif    
    if (bits_size * 8 <= (unsigned)curve->num_n_bits) {
        return;
    }
    shift = bits_size * 8 - curve->num_n_bits;
    carry = 0;
    ptr = native + num_n_words;
    while (ptr-- > native) {
        uECC_word_t temp = *ptr;
        *ptr = (temp >> shift) | carry;
        carry = temp << (uECC_WORD_BITS - shift);
    }

    /* Reduce mod curve_n */
    if (uECC_vli_cmp_unsafe(curve->n, native, num_n_words) != 1) {
        uECC_vli_sub(native, native, curve->n, num_n_words);
    }
}

static int uECC_sign_with_k(const uint8_t *private_key,
                            const uint8_t *message_hash,
                            unsigned hash_size,
                            uECC_word_t *k,
                            uint8_t *signature,
                            uECC_Curve curve) {

    uECC_word_t tmp[uECC_MAX_WORDS];
    uECC_word_t s[uECC_MAX_WORDS];
    uECC_word_t *k2[2] = {tmp, s};
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *p = (uECC_word_t *)signature;
#else
    uECC_word_t p[uECC_MAX_WORDS * 2];
#endif
    uECC_word_t carry;
    wordcount_t num_words = curve->num_words;
    wordcount_t num_n_words = BITS_TO_WORDS(curve->num_n_bits);
    bitcount_t num_n_bits = curve->num_n_bits;

    /* Make sure 0 < k < curve_n */
    if (uECC_vli_isZero(k, num_words) || uECC_vli_cmp(curve->n, k, num_n_words) != 1) {
        return 0;
    }

    carry = regularize_k(k, tmp, s, curve);
    EccPoint_mult(p, curve->G, k2[!carry], 0, num_n_bits + 1, curve);
    if (uECC_vli_isZero(p, num_words)) {
        return 0;
    }

    /* If an RNG function was specified, get a random number
       to prevent side channel analysis of k. */
    if (!g_rng_function) {
        uECC_vli_clear(tmp, num_n_words);
        tmp[0] = 1;
    } else if (!uECC_generate_random_int(tmp, curve->n, num_n_words)) {
        return 0;
    }

    /* Prevent side channel analysis of uECC_vli_modInv() to determine
       bits of k / the private key by premultiplying by a random number */
    uECC_vli_modMult(k, k, tmp, curve->n, num_n_words); /* k' = rand * k */
    uECC_vli_modInv(k, k, curve->n, num_n_words);       /* k = 1 / k' */
    uECC_vli_modMult(k, k, tmp, curve->n, num_n_words); /* k = 1 / k */

#if uECC_VLI_NATIVE_LITTLE_ENDIAN == 0
    uECC_vli_nativeToBytes(signature, curve->num_bytes, p); /* store r */
#endif

#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) tmp, private_key, BITS_TO_BYTES(curve->num_n_bits));
#else
    uECC_vli_bytesToNative(tmp, private_key, BITS_TO_BYTES(curve->num_n_bits)); /* tmp = d */
#endif

    s[num_n_words - 1] = 0;
    uECC_vli_set(s, p, num_words);
    uECC_vli_modMult(s, tmp, s, curve->n, num_n_words); /* s = r*d */

    bits2int(tmp, message_hash, hash_size, curve);
    uECC_vli_modAdd(s, tmp, s, curve->n, num_n_words); /* s = e + r*d */
    uECC_vli_modMult(s, s, k, curve->n, num_n_words);  /* s = (e + r*d) / k */
    if (uECC_vli_numBits(s, num_n_words) > (bitcount_t)curve->num_bytes * 8) {
        return 0;
    }
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) signature + curve->num_bytes, (uint8_t *) s, curve->num_bytes);
#else
    uECC_vli_nativeToBytes(signature + curve->num_bytes, curve->num_bytes, s);
#endif    
    return 1;
}

int uECC_sign(const uint8_t *private_key,
              const uint8_t *message_hash,
              unsigned hash_size,
              uint8_t *signature,
              uECC_Curve curve) {
    uECC_word_t k[uECC_MAX_WORDS];
    uECC_word_t tries;

    for (tries = 0; tries < uECC_RNG_MAX_TRIES; ++tries) {
        if (!uECC_generate_random_int(k, curve->n, BITS_TO_WORDS(curve->num_n_bits))) {
            return 0;
        }

        if (uECC_sign_with_k(private_key, message_hash, hash_size, k, signature, curve)) {
            return 1;
        }
    }
    return 0;
}

/* Compute an HMAC using K as a key (as in RFC 6979). Note that K is always
   the same size as the hash result size. */
static void HMAC_init(const uECC_HashContext *hash_context, const uint8_t *K) {
    uint8_t *pad = hash_context->tmp + 2 * hash_context->result_size;
    unsigned i;
    for (i = 0; i < hash_context->result_size; ++i)
        pad[i] = K[i] ^ 0x36;
    for (; i < hash_context->block_size; ++i)
        pad[i] = 0x36;

    hash_context->init_hash(hash_context);
    hash_context->update_hash(hash_context, pad, hash_context->block_size);
}

static void HMAC_update(const uECC_HashContext *hash_context,
                        const uint8_t *message,
                        unsigned message_size) {
    hash_context->update_hash(hash_context, message, message_size);
}

static void HMAC_finish(const uECC_HashContext *hash_context,
                        const uint8_t *K,
                        uint8_t *result) {
    uint8_t *pad = hash_context->tmp + 2 * hash_context->result_size;
    unsigned i;
    for (i = 0; i < hash_context->result_size; ++i)
        pad[i] = K[i] ^ 0x5c;
    for (; i < hash_context->block_size; ++i)
        pad[i] = 0x5c;

    hash_context->finish_hash(hash_context, result);

    hash_context->init_hash(hash_context);
    hash_context->update_hash(hash_context, pad, hash_context->block_size);
    hash_context->update_hash(hash_context, result, hash_context->result_size);
    hash_context->finish_hash(hash_context, result);
}

/* V = HMAC_K(V) */
static void update_V(const uECC_HashContext *hash_context, uint8_t *K, uint8_t *V) {
    HMAC_init(hash_context, K);
    HMAC_update(hash_context, V, hash_context->result_size);
    HMAC_finish(hash_context, K, V);
}

/* Deterministic signing, similar to RFC 6979. Differences are:
    * We just use H(m) directly rather than bits2octets(H(m))
      (it is not reduced modulo curve_n).
    * We generate a value for k (aka T) directly rather than converting endianness.

   Layout of hash_context->tmp: <K> | <V> | (1 byte overlapped 0x00 or 0x01) / <HMAC pad> */
int uECC_sign_deterministic(const uint8_t *private_key,
                            const uint8_t *message_hash,
                            unsigned hash_size,
                            const uECC_HashContext *hash_context,
                            uint8_t *signature,
                            uECC_Curve curve) {
    uint8_t *K = hash_context->tmp;
    uint8_t *V = K + hash_context->result_size;
    wordcount_t num_bytes = curve->num_bytes;
    wordcount_t num_n_words = BITS_TO_WORDS(curve->num_n_bits);
    bitcount_t num_n_bits = curve->num_n_bits;
    uECC_word_t tries;
    unsigned i;
    for (i = 0; i < hash_context->result_size; ++i) {
        V[i] = 0x01;
        K[i] = 0;
    }

    /* K = HMAC_K(V || 0x00 || int2octets(x) || h(m)) */
    HMAC_init(hash_context, K);
    V[hash_context->result_size] = 0x00;
    HMAC_update(hash_context, V, hash_context->result_size + 1);
    HMAC_update(hash_context, private_key, num_bytes);
    HMAC_update(hash_context, message_hash, hash_size);
    HMAC_finish(hash_context, K, K);

    update_V(hash_context, K, V);

    /* K = HMAC_K(V || 0x01 || int2octets(x) || h(m)) */
    HMAC_init(hash_context, K);
    V[hash_context->result_size] = 0x01;
    HMAC_update(hash_context, V, hash_context->result_size + 1);
    HMAC_update(hash_context, private_key, num_bytes);
    HMAC_update(hash_context, message_hash, hash_size);
    HMAC_finish(hash_context, K, K);

    update_V(hash_context, K, V);

    for (tries = 0; tries < uECC_RNG_MAX_TRIES; ++tries) {
        uECC_word_t T[uECC_MAX_WORDS];
        uint8_t *T_ptr = (uint8_t *)T;
        wordcount_t T_bytes = 0;
        for (;;) {
            update_V(hash_context, K, V);
            for (i = 0; i < hash_context->result_size; ++i) {
                T_ptr[T_bytes++] = V[i];
                if (T_bytes >= num_n_words * uECC_WORD_SIZE) {
                    goto filled;
                }
            }
        }
    filled:
        if ((bitcount_t)num_n_words * uECC_WORD_SIZE * 8 > num_n_bits) {
            uECC_word_t mask = (uECC_word_t)-1;
            T[num_n_words - 1] &=
                mask >> ((bitcount_t)(num_n_words * uECC_WORD_SIZE * 8 - num_n_bits));
        }

        if (uECC_sign_with_k(private_key, message_hash, hash_size, T, signature, curve)) {
            return 1;
        }

        /* K = HMAC_K(V || 0x00) */
        HMAC_init(hash_context, K);
        V[hash_context->result_size] = 0x00;
        HMAC_update(hash_context, V, hash_context->result_size + 1);
        HMAC_finish(hash_context, K, K);

        update_V(hash_context, K, V);
    }
    return 0;
}

static bitcount_t smax(bitcount_t a, bitcount_t b) {
    return (a > b ? a : b);
}

int uECC_verify(const uint8_t *public_key,
                const uint8_t *message_hash,
                unsigned hash_size,
                const uint8_t *signature,
                uECC_Curve curve) {
    uECC_word_t u1[uECC_MAX_WORDS], u2[uECC_MAX_WORDS];
    uECC_word_t z[uECC_MAX_WORDS];
    uECC_word_t sum[uECC_MAX_WORDS * 2];
    uECC_word_t rx[uECC_MAX_WORDS];
    uECC_word_t ry[uECC_MAX_WORDS];
    uECC_word_t tx[uECC_MAX_WORDS];
    uECC_word_t ty[uECC_MAX_WORDS];
    uECC_word_t tz[uECC_MAX_WORDS];
    const uECC_word_t *points[4];
    const uECC_word_t *point;
    bitcount_t num_bits;
    bitcount_t i;
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *public = (uECC_word_t *)public_key;
#else
    uECC_word_t public[uECC_MAX_WORDS * 2];
#endif    
    uECC_word_t r[uECC_MAX_WORDS], s[uECC_MAX_WORDS];
    wordcount_t num_words = curve->num_words;
    wordcount_t num_n_words = BITS_TO_WORDS(curve->num_n_bits);

    rx[num_n_words - 1] = 0;
    r[num_n_words - 1] = 0;
    s[num_n_words - 1] = 0;

#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) r, signature, curve->num_bytes);
    bcopy((uint8_t *) s, signature + curve->num_bytes, curve->num_bytes);
#else
    uECC_vli_bytesToNative(public, public_key, curve->num_bytes);
    uECC_vli_bytesToNative(
        public + num_words, public_key + curve->num_bytes, curve->num_bytes);
    uECC_vli_bytesToNative(r, signature, curve->num_bytes);
    uECC_vli_bytesToNative(s, signature + curve->num_bytes, curve->num_bytes);
#endif

    /* r, s must not be 0. */
    if (uECC_vli_isZero(r, num_words) || uECC_vli_isZero(s, num_words)) {
        return 0;
    }

    /* r, s must be < n. */
    if (uECC_vli_cmp_unsafe(curve->n, r, num_n_words) != 1 ||
            uECC_vli_cmp_unsafe(curve->n, s, num_n_words) != 1) {
        return 0;
    }

    /* Calculate u1 and u2. */
    uECC_vli_modInv(z, s, curve->n, num_n_words); /* z = 1/s */
    u1[num_n_words - 1] = 0;
    bits2int(u1, message_hash, hash_size, curve);
    uECC_vli_modMult(u1, u1, z, curve->n, num_n_words); /* u1 = e/s */
    uECC_vli_modMult(u2, r, z, curve->n, num_n_words); /* u2 = r/s */

    /* Calculate sum = G + Q. */
    uECC_vli_set(sum, public, num_words);
    uECC_vli_set(sum + num_words, public + num_words, num_words);
    uECC_vli_set(tx, curve->G, num_words);
    uECC_vli_set(ty, curve->G + num_words, num_words);
    uECC_vli_modSub(z, sum, tx, curve->p, num_words); /* z = x2 - x1 */
    XYcZ_add(tx, ty, sum, sum + num_words, curve);
    uECC_vli_modInv(z, z, curve->p, num_words); /* z = 1/z */
    apply_z(sum, sum + num_words, z, curve);

    /* Use Shamir's trick to calculate u1*G + u2*Q */
    points[0] = 0;
    points[1] = curve->G;
    points[2] = public;
    points[3] = sum;
    num_bits = smax(uECC_vli_numBits(u1, num_n_words),
                    uECC_vli_numBits(u2, num_n_words));

    point = points[(!!uECC_vli_testBit(u1, num_bits - 1)) |
                   ((!!uECC_vli_testBit(u2, num_bits - 1)) << 1)];
    uECC_vli_set(rx, point, num_words);
    uECC_vli_set(ry, point + num_words, num_words);
    uECC_vli_clear(z, num_words);
    z[0] = 1;

    for (i = num_bits - 2; i >= 0; --i) {
        uECC_word_t index;
        curve->double_jacobian(rx, ry, z, curve);

        index = (!!uECC_vli_testBit(u1, i)) | ((!!uECC_vli_testBit(u2, i)) << 1);
        point = points[index];
        if (point) {
            uECC_vli_set(tx, point, num_words);
            uECC_vli_set(ty, point + num_words, num_words);
            apply_z(tx, ty, z, curve);
            uECC_vli_modSub(tz, rx, tx, curve->p, num_words); /* Z = x2 - x1 */
            XYcZ_add(tx, ty, rx, ry, curve);
            uECC_vli_modMult_fast(z, z, tz, curve);
        }
    }

    uECC_vli_modInv(z, z, curve->p, num_words); /* Z = 1/Z */
    apply_z(rx, ry, z, curve);

    /* v = x1 (mod n) */
    if (uECC_vli_cmp_unsafe(curve->n, rx, num_n_words) != 1) {
        uECC_vli_sub(rx, rx, curve->n, num_n_words);
    }

    /* Accept only if v == r. */
    return (int)(uECC_vli_equal(rx, r, num_words));
}

#if uECC_ENABLE_VLI_API

unsigned uECC_curve_num_words(uECC_Curve curve) {
    return curve->num_words;
}

unsigned uECC_curve_num_bytes(uECC_Curve curve) {
    return curve->num_bytes;
}

unsigned uECC_curve_num_bits(uECC_Curve curve) {
    return curve->num_bytes * 8;
}

unsigned uECC_curve_num_n_words(uECC_Curve curve) {
    return BITS_TO_WORDS(curve->num_n_bits);
}

unsigned uECC_curve_num_n_bytes(uECC_Curve curve) {
    return BITS_TO_BYTES(curve->num_n_bits);
}

unsigned uECC_curve_num_n_bits(uECC_Curve curve) {
    return curve->num_n_bits;
}

const uECC_word_t *uECC_curve_p(uECC_Curve curve) {
    return curve->p;
}

const uECC_word_t *uECC_curve_n(uECC_Curve curve) {
    return curve->n;
}

const uECC_word_t *uECC_curve_G(uECC_Curve curve) {
    return curve->G;
}

const uECC_word_t *uECC_curve_b(uECC_Curve curve) {
    return curve->b;
}

#if uECC_SUPPORT_COMPRESSED_POINT
void uECC_vli_mod_sqrt(uECC_word_t *a, uECC_Curve curve) {
    curve->mod_sqrt(a, curve);
}
#endif

void uECC_vli_mmod_fast(uECC_word_t *result, uECC_word_t *product, uECC_Curve curve) {
#if (uECC_OPTIMIZATION_LEVEL > 0)
    curve->mmod_fast(result, product);
#else
    uECC_vli_mmod(result, product, curve->p, curve->num_words);
#endif
}

void uECC_point_mult(uECC_word_t *result,
                     const uECC_word_t *point,
                     const uECC_word_t *scalar,
                     uECC_Curve curve) {
    uECC_word_t tmp1[uECC_MAX_WORDS];
    uECC_word_t tmp2[uECC_MAX_WORDS];
    uECC_word_t *p2[2] = {tmp1, tmp2};
    uECC_word_t carry = regularize_k(scalar, tmp1, tmp2, curve);

    EccPoint_mult(result, point, p2[!carry], 0, curve->num_n_bits + 1, curve);
}

#endif /* uECC_ENABLE_VLI_API */
#include "telehash.h"
#include "telehash.h"
#include "telehash.h"
#include <string.h>

static uint8_t _initialized = 0;

// any process-wide one-time initialization
uint8_t e3x_init(lob_t options)
{
  uint8_t err;
  if(_initialized) return 0;
  util_sys_random_init();
  err = e3x_cipher_init(options);
  if(err) return err;
  _initialized = 1;
  return 0;
}

// just check every cipher set for any error string
uint8_t *e3x_err(void)
{
  uint8_t i;
  uint8_t *err = NULL;
  for(i=0; i<CS_MAX; i++)
  {
    if(e3x_cipher_sets[i] && e3x_cipher_sets[i]->err) err = e3x_cipher_sets[i]->err();
    if(err) return err;
  }
  return err;
}

// generate all the keypairs
lob_t e3x_generate(void)
{
  uint8_t i, err = 0;
  lob_t keys, secrets;
  keys = lob_new();
  secrets = lob_chain(keys);
  for(err=i=0; i<CS_MAX; i++)
  {
    if(err || !e3x_cipher_sets[i] || !e3x_cipher_sets[i]->generate) continue;
    err = e3x_cipher_sets[i]->generate(keys, secrets);
  }
  if(err) return lob_free(secrets);
  return secrets;
}


static uint8_t (*frandom)(void) = (uint8_t (*)(void))util_sys_random;

// set a callback for random
void e3x_random(uint8_t (*frand)(void))
{
  frandom = frand;
}

// random bytes, from a supported cipher set
uint8_t *e3x_rand(uint8_t *bytes, size_t len)
{
  uint8_t *x = bytes;
  if(!bytes || !len) return bytes;
  if(e3x_cipher_default && e3x_cipher_default->rand) return e3x_cipher_default->rand(bytes, len);

  // crypto lib didn't provide one, use platform's RNG
  while(len-- > 0)
  {
    *x = frandom();
    x++;
  }
  return bytes;
}

// sha256 hashing, from one of the cipher sets
uint8_t *e3x_hash(uint8_t *in, size_t len, uint8_t *out32)
{
  if(!in || !out32) return out32;
  if(!e3x_cipher_default)
  {
    LOG("e3x not initialized, no cipher_set");
    memset(out32,0,32);
    return out32;
  }
  return e3x_cipher_default->hash(in, len, out32);
}


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "telehash.h"
#include "telehash.h"

// load secrets/keys to create a new local endpoint
e3x_self_t e3x_self_new(lob_t secrets, lob_t keys)
{
  uint8_t i, csids = 0;
  e3x_self_t self;
  if(!keys) keys = lob_linked(secrets); // convenience
  if(!keys) return NULL;

  if(!(self = malloc(sizeof (struct e3x_self_struct)))) return NULL;
  memset(self,0,sizeof (struct e3x_self_struct));

  // give each cset a chance to make a local
  for(i=0; i<CS_MAX; i++)
  {
    if(!e3x_cipher_sets[i] || !e3x_cipher_sets[i]->local_new) continue;
    self->locals[i] = e3x_cipher_sets[i]->local_new(keys, secrets);
    if(!self->locals[i]) continue;
    // make a copy of the binary keys for comparison logic
    self->keys[i] = lob_get_base32(keys, e3x_cipher_sets[i]->hex);
    csids++;
  }

  if(!csids)
  {
    e3x_self_free(self);
    return LOG("self failed for %.*s",keys->head_len,keys->head);
  }

  LOG("self created with %d csids",csids);
  return self;
}

// any exchanges must have been free'd first
void e3x_self_free(e3x_self_t self)
{
  uint8_t i;
  if(!self) return;

  // free any locals created
  for(i=0; i<CS_MAX; i++)
  {
    if(!self->locals[i] || !e3x_cipher_sets[i]) continue;
    e3x_cipher_sets[i]->local_free(self->locals[i]);
    lob_free(self->keys[i]);
  }

  free(self);
  return;
}

// try to decrypt any message sent to us, returns the inner
lob_t e3x_self_decrypt(e3x_self_t self, lob_t message)
{
  e3x_cipher_t cs;
  if(!self || !message) return LOG("bad args");
  if(message->head_len != 1) return LOG("invalid message");
  cs = e3x_cipher_set(message->head[0],NULL);
  if(!cs) return LOG("no cipherset %2x",message->head[0]);
  return cs->local_decrypt(self->locals[cs->id],message);
}

// generate a signature for the data
lob_t e3x_self_sign(e3x_self_t self, lob_t args, uint8_t *data, size_t len)
{
  local_t local = NULL;
  e3x_cipher_t cs = NULL;
  char *alg = lob_get(args,"alg");
  if(!data || !len || !alg) return LOG("bad args");
  cs = e3x_cipher_set(0,alg);
  if(!cs || !cs->local_sign) return LOG("no signing support for %s",alg);
  if(self) local = self->locals[cs->id];
  return cs->local_sign(local,args,data,len);
}
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "telehash.h"
#include "telehash.h"

// make a new exchange
// packet must contain the raw key in the body
e3x_exchange_t e3x_exchange_new(e3x_self_t self, uint8_t csid, lob_t key)
{
  uint16_t i;
  uint8_t token[16];
  e3x_exchange_t x;
  remote_t remote;
  e3x_cipher_t cs = NULL;

  if(!self || !csid || !key || !key->body_len) return LOG("bad args");

  // find matching csid
  for(i=0; i<CS_MAX; i++)
  {
    if(!e3x_cipher_sets[i]) continue;
    if(e3x_cipher_sets[i]->csid != csid) continue;
    if(!self->locals[i]) continue;
    cs = e3x_cipher_sets[i];
    break;
  }

  if(!cs) return LOG("unsupported csid %x",csid);
  remote = cs->remote_new(key, token);
  if(!remote) return LOG("failed to create %x remote %s",csid,cs->err());

  if(!(x = malloc(sizeof (struct e3x_exchange_struct)))) return NULL;
  memset(x,0,sizeof (struct e3x_exchange_struct));

  x->csid = csid;
  x->remote = remote;
  x->cs = cs;
  x->self = self;
  memcpy(x->token,token,16);

  // determine order, if we sort first, we're even
  for(i = 0; i < key->body_len; i++)
  {
    if(key->body[i] == self->keys[cs->id]->body[i]) continue;
    x->order = (key->body[i] > self->keys[cs->id]->body[i]) ? 2 : 1;
    break;
  }
  x->cid = x->order;

  return x;
}

void e3x_exchange_free(e3x_exchange_t x)
{
  if(!x) return;
  x->cs->remote_free(x->remote);
  x->cs->ephemeral_free(x->ephem);
  free(x);
}

// these require a self (local) and an exchange (remote) but are exchange independent
// will safely set/increment at if 0
lob_t e3x_exchange_message(e3x_exchange_t x, lob_t inner)
{
  if(!x || !inner) return LOG("bad args");
  return x->cs->remote_encrypt(x->remote,x->self->locals[x->cs->id],inner);
}

// any handshake verify fail (lower seq), always resend handshake
uint8_t e3x_exchange_verify(e3x_exchange_t x, lob_t outer)
{
  if(!x || !outer) return 1;
  return x->cs->remote_verify(x->remote,x->self->locals[x->cs->id],outer);
}

uint8_t e3x_exchange_validate(e3x_exchange_t x, lob_t args, lob_t sig, uint8_t *data, size_t len)
{
  remote_t remote = NULL;
  e3x_cipher_t cs = NULL;
  char *alg = lob_get(args,"alg");
  if(!data || !len || !alg) return 1;
  cs = e3x_cipher_set(0,alg);
  if(!cs || !cs->remote_validate)
  {
    LOG("no validate support for %s",alg);
    return 1;
  }
  if(x && x->cs == cs) remote = x->remote;
  return cs->remote_validate(remote,args,sig,data,len);
}

// will return the current outgoing at value, optional arg to update it
uint32_t e3x_exchange_out(e3x_exchange_t x, uint32_t at)
{
  if(!x) return 0;

  // if there's a base, update at
  if(at && at > x->out)
  {
    // make sure at matches order
    x->out = at;
    if(x->order == 2)
    {
      if(x->out % 2 != 0) x->out++;
    }else{
      if(x->out % 2 == 0) x->out++;
    }
  }

  return x->out;
}

// return the current incoming at value, optional arg to update it
uint32_t e3x_exchange_in(e3x_exchange_t x, uint32_t at)
{
  if(!x) return 0;

  // ensure at is newer and valid, or acking our out
  if(at && at > x->in && at >= x->out && (((at % 2)+1) == x->order || at == x->out)) x->in = at;

  return x->in;
}

// drops ephemeral state, out=0
e3x_exchange_t e3x_exchange_down(e3x_exchange_t x)
{
  if(!x) return NULL;
  x->out = 0;
  if(x->ephem)
  {
    x->cs->ephemeral_free(x->ephem);
    x->ephem = NULL;
    memset(x->eid,0,16);
    x->last = 0;
  }
  return x;
}

// synchronize to incoming ephemeral key and set out at = in at, returns x if success, NULL if not
e3x_exchange_t e3x_exchange_sync(e3x_exchange_t x, lob_t outer)
{
  ephemeral_t ephem;
  if(!x || !outer) return LOG("bad args");
  if(outer->body_len < 16) return LOG("outer too small");

  if(x->in > x->out) x->out = x->in;

  // if the incoming ephemeral key is different, create a new ephemeral
  if(util_ct_memcmp(outer->body,x->eid,16) != 0)
  {
    ephem = x->cs->ephemeral_new(x->remote,outer);
    if(!ephem) return LOG("ephemeral creation failed %s",x->cs->err());
    x->cs->ephemeral_free(x->ephem);
    x->ephem = ephem;
    memcpy(x->eid,outer->body,16);
    // reset incoming channel id validation
    x->last = 0;
  }

  return x;
}

// just a convenience, generates handshake w/ current e3x_exchange_at value
lob_t e3x_exchange_handshake(e3x_exchange_t x, lob_t inner)
{
  lob_t tmp;
  uint8_t i;
  uint8_t local = 0;
  if(!x) return LOG("invalid args");
  if(!x->out) return LOG("no out set");

  // create deprecated key handshake inner from all supported csets
  if(!inner)
  {
    local = 1;
    inner = lob_new();
    lob_set(inner, "type", "key");
    // loop through all ciphersets for any keys
    for(i=0; i<CS_MAX; i++)
    {
      if(!(tmp = x->self->keys[i])) continue;
      // this csid's key is the body, rest is intermediate in json
      if(e3x_cipher_sets[i] == x->cs)
      {
        lob_body(inner,tmp->body,tmp->body_len);
      }else{
        uint8_t hash[32];
        e3x_hash(tmp->body,tmp->body_len,hash);
        lob_set_base32(inner,e3x_cipher_sets[i]->hex,hash,32);
      }
    }
  }

  // set standard values
  lob_set_uint(inner,"at",x->out);

  tmp = e3x_exchange_message(x, inner);
  if(!local) return tmp;
  return lob_link(tmp, inner);
}

// simple encrypt/decrypt conversion of any packet for channels
lob_t e3x_exchange_receive(e3x_exchange_t x, lob_t outer)
{
  lob_t inner;
  if(!x || !outer) return LOG("invalid args");
  if(!x->ephem) return LOG("no handshake");
  inner = x->cs->ephemeral_decrypt(x->ephem,outer);
  if(!inner) return LOG("decryption failed %s",x->cs->err());
  LOG("decrypted head %d body %d",inner->head_len,inner->body_len);
  return inner;
}

// comes from channel
lob_t e3x_exchange_send(e3x_exchange_t x, lob_t inner)
{
  lob_t outer;
  if(!x || !inner) return LOG("invalid args");
  if(!x->ephem) return LOG("no handshake");
  LOG("encrypting head %d body %d",inner->head_len,inner->body_len);
  outer = x->cs->ephemeral_encrypt(x->ephem,inner);
  if(!outer) return LOG("encryption failed %s",x->cs->err());
  return outer;
}

// validate the next incoming channel id from the packet, or return the next avail outgoing channel id
uint32_t e3x_exchange_cid(e3x_exchange_t x, lob_t incoming)
{
  uint32_t cid;
  if(!x) return 0;

  // in outgoing mode, just return next valid one
  if(!incoming)
  {
    cid = x->cid;
    x->cid += 2;
    return cid;
  }

  // incoming mode, verify it
  if(!(cid = lob_get_uint(incoming,"c"))) return 0;
  if(cid <= x->last) return 0; // can't re-use old ones
  // make sure it's even/odd properly
  if((cid % 2) == (x->cid % 2)) return 0;
  x->last = cid; // track the highest
  return cid;
}

uint8_t *e3x_exchange_token(e3x_exchange_t x)
{
  if(!x) return NULL;
  return x->token;
}
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "telehash.h"
#include "telehash.h"

e3x_cipher_t e3x_cipher_sets[CS_MAX];
e3x_cipher_t e3x_cipher_default = NULL;

uint8_t e3x_cipher_init(lob_t options)
{
  e3x_cipher_default = NULL;
  memset(e3x_cipher_sets, 0, CS_MAX * sizeof(e3x_cipher_t));
  
  e3x_cipher_sets[CS_1a] = cs1a_init(options);
  if(e3x_cipher_sets[CS_1a]) e3x_cipher_default = e3x_cipher_sets[CS_1a];
  if(lob_get(options, "err")) return 1;
  
  if(lob_get_cmp(options, "force", "1a") == 0) return 0;

  e3x_cipher_sets[CS_2a] = cs2a_init(options);
  if(e3x_cipher_sets[CS_2a]) e3x_cipher_default = e3x_cipher_sets[CS_2a];
  if(lob_get(options, "err")) return 1;

  e3x_cipher_sets[CS_3a] = cs3a_init(options);
  if(e3x_cipher_sets[CS_3a]) e3x_cipher_default = e3x_cipher_sets[CS_3a];
  if(lob_get(options, "err")) return 1;

  return 0;
}

e3x_cipher_t e3x_cipher_set(uint8_t csid, char *str)
{
  uint8_t i;
  
  if(!csid && str && strlen(str) == 2) util_unhex(str,2,&csid);

  for(i=0; i<CS_MAX; i++)
  {
    if(!e3x_cipher_sets[i]) continue;
    if(e3x_cipher_sets[i]->csid == csid) return e3x_cipher_sets[i];
    // if they list alg's they support, match on that too
    if(str && e3x_cipher_sets[i]->alg && strstr(e3x_cipher_sets[i]->alg,str)) return e3x_cipher_sets[i];
  }

  return NULL;
}

#include "telehash.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "telehash.h"

// internally handle list of triggers active on the mesh
typedef struct on_struct
{
  char *id; // used to store in index
  
  void (*free)(mesh_t mesh); // relese resources
  void (*link)(link_t link); // when a link is created, and again when exchange is created
  link_t (*path)(link_t link, lob_t path); // convert path->pipe
  lob_t (*open)(link_t link, lob_t open); // incoming channel requests
  link_t (*discover)(mesh_t mesh, lob_t discovered); // incoming unknown hashnames
  
  struct on_struct *next;
} *on_t;
on_t on_get(mesh_t mesh, char *id);
on_t on_free(on_t on);

mesh_t mesh_new(void)
{
  mesh_t mesh;
  
  // make sure we've initialized
  if(e3x_init(NULL)) return LOG_ERROR("e3x init failed");

  if(!(mesh = malloc(sizeof (struct mesh_struct)))) return NULL;
  memset(mesh, 0, sizeof(struct mesh_struct));
  
  LOG_INFO("mesh created version %d.%d.%d",TELEHASH_VERSION_MAJOR,TELEHASH_VERSION_MINOR,TELEHASH_VERSION_PATCH);

  return mesh;
}

mesh_t mesh_free(mesh_t mesh)
{
  on_t on;
  if(!mesh) return NULL;

  // free all links first
  link_t link, next;
  for(link = mesh->links;link;link = next)
  {
    next = link->next;
    link_free(link);
  }
  
  // free any triggers first
  while(mesh->on)
  {
    on = mesh->on;
    mesh->on = on->next;
    if(on->free) on->free(mesh);
    free(on->id);
    free(on);
  }

  lob_free(mesh->keys);
  lob_free(mesh->paths);
  hashname_free(mesh->id);
  e3x_self_free(mesh->self);
  if(mesh->ipv4_local) free(mesh->ipv4_local);
  if(mesh->ipv4_public) free(mesh->ipv4_public);

  free(mesh);
  return NULL;
}

// must be called to initialize to a hashname from keys/secrets, return !0 if failed
uint8_t mesh_load(mesh_t mesh, lob_t secrets, lob_t keys)
{
  if(!mesh || !secrets || !keys) return 1;
  if(!(mesh->self = e3x_self_new(secrets, keys))) return 2;
  mesh->keys = lob_copy(keys);
  mesh->id = hashname_dup(hashname_vkeys(mesh->keys));
  LOG_INFO("mesh is %s",hashname_short(mesh->id));
  return 0;
}

// creates a new mesh identity, returns secrets
lob_t mesh_generate(mesh_t mesh)
{
  lob_t secrets;
  if(!mesh || mesh->self) return LOG_ERROR("invalid mesh");
  secrets = e3x_generate();
  if(!secrets) return LOG_ERROR("failed to generate %s",e3x_err());
  if(mesh_load(mesh, secrets, lob_linked(secrets))) return lob_free(secrets);
  return secrets;
}

// simple accessors
hashname_t mesh_id(mesh_t mesh)
{
  if(!mesh) return NULL;
  return mesh->id;
}

lob_t mesh_keys(mesh_t mesh)
{
  if(!mesh) return NULL;
  return mesh->keys;
}

// generate json of mesh keys and current paths
lob_t mesh_json(mesh_t mesh)
{
  lob_t json, paths;
  if(!mesh) return LOG_ERROR("bad args");

  json = lob_new();
  lob_set(json,"hashname",hashname_char(mesh->id));
  lob_set_raw(json,"keys",0,(char*)mesh->keys->head,mesh->keys->head_len);
  paths = lob_array(mesh->paths);
  lob_set_raw(json,"paths",0,(char*)paths->head,paths->head_len);
  lob_free(paths);
  return json;
}

// generate json for all links, returns lob list
lob_t mesh_links(mesh_t mesh)
{
  lob_t links = NULL;
  link_t link;

  for(link = mesh->links;link;link = link->next)
  {
    links = lob_push(links,link_json(link));
  }
  return links;
}

// process any channel timeouts based on the current/given time
mesh_t mesh_process(mesh_t mesh, uint32_t now)
{
  link_t link, next;
  if(!mesh || !now) return LOG("bad args");
  for(link = mesh->links;link;link = next)
  {
    next = link->next;
    link_process(link, now);
  }
  
  return mesh;
}

link_t mesh_add(mesh_t mesh, lob_t json)
{
  link_t link;
  lob_t keys, paths;
  uint8_t csid;

  if(!mesh || !json) return LOG("bad args");
  LOG("mesh add %s",lob_json(json));
  link = link_get(mesh, hashname_vchar(lob_get(json,"hashname")));
  keys = lob_get_json(json,"keys");
  paths = lob_get_array(json,"paths");
  if(!link) link = link_get_keys(mesh, keys);
  if(!link) LOG("no hashname");
  
  LOG("loading keys from %s",lob_json(keys));
  if(keys && (csid = hashname_id(mesh->keys,keys))) link_load(link, csid, keys);

  // handle any pipe/paths
  lob_t path;
  for(path=paths;path;path = lob_next(path)) mesh_path(mesh,link,path);
  
  lob_free(keys);
  lob_freeall(paths);

  return link;
}

link_t mesh_linked(mesh_t mesh, char *hn, size_t len)
{
  link_t link;
  if(!mesh || !hn) return NULL;
  if(!len) len = strlen(hn);
  
  for(link = mesh->links;link;link = link->next) if(strncmp(hashname_char(link->id),hn,len) == 0) return link;
  
  return NULL;
}

link_t mesh_linkid(mesh_t mesh, hashname_t id)
{
  link_t link;
  if(!mesh || !id) return NULL;
  
  for(link = mesh->links;link;link = link->next) if(hashname_scmp(link->id,id) == 0) return link;
  
  return NULL;
}

// remove this link, will event it down and clean up during next process()
mesh_t mesh_unlink(link_t link)
{
  if(!link) return NULL;
  link->csid = 0; // removal indicator
  return link->mesh;
}

// create our generic callback linked list entry
on_t on_get(mesh_t mesh, char *id)
{
  on_t on;
  
  if(!mesh || !id) return LOG("bad args");
  for(on = mesh->on; on; on = on->next) if(util_cmp(on->id,id) == 0) return on;

  if(!(on = malloc(sizeof (struct on_struct)))) return LOG("OOM");
  memset(on, 0, sizeof(struct on_struct));
  on->id = strdup(id);
  on->next = mesh->on;
  mesh->on = on;
  return on;
}

void mesh_on_free(mesh_t mesh, char *id, void (*free)(mesh_t mesh))
{
  on_t on = on_get(mesh, id);
  if(on) on->free = free;
}

void mesh_on_path(mesh_t mesh, char *id, link_t (*path)(link_t link, lob_t path))
{
  on_t on = on_get(mesh, id);
  if(on) on->path = path;
}

link_t mesh_path(mesh_t mesh, link_t link, lob_t path)
{
  if(!mesh || !link || !path) return NULL;

  on_t on;
  for(on = mesh->on; on; on = on->next)
  {
    if(on->path && on->path(link, path)) return link;
  }
  return LOG("no pipe for path %.*s",path->head_len,path->head);
}

void mesh_on_link(mesh_t mesh, char *id, void (*link)(link_t link))
{
  on_t on = on_get(mesh, id);
  if(on) on->link = link;
}

void mesh_link(mesh_t mesh, link_t link)
{
  // event notifications
  on_t on;
  for(on = mesh->on; on; on = on->next) if(on->link) on->link(link);
}

void mesh_on_open(mesh_t mesh, char *id, lob_t (*open)(link_t link, lob_t open))
{
  on_t on = on_get(mesh, id);
  if(on) on->open = open;
}

lob_t mesh_open(mesh_t mesh, link_t link, lob_t open)
{
  on_t on;
  for(on = mesh->on; open && on; on = on->next) if(on->open) open = on->open(link, open);
  return open;
}

void mesh_on_discover(mesh_t mesh, char *id, link_t (*discover)(mesh_t mesh, lob_t discovered))
{
  on_t on = on_get(mesh, id);
  if(on) on->discover = discover;
}

void mesh_discover(mesh_t mesh, lob_t discovered)
{
  on_t on;
  LOG("running mesh discover with %s",lob_json(discovered));
  for(on = mesh->on; on; on = on->next) if(on->discover) on->discover(mesh, discovered);
}

// process any unencrypted handshake packet
link_t mesh_receive_handshake(mesh_t mesh, lob_t handshake)
{
  uint32_t now;
  hashname_t from = NULL;
  link_t link;

  if(!mesh || !handshake) return LOG("bad args");
  if(!lob_get(handshake,"id"))
  {
    LOG("bad handshake, no id: %s",lob_json(handshake));
    lob_free(handshake);
    return NULL;
  }
  now = util_sys_seconds();
  
  // normalize handshake
  handshake->id = now; // save when we cached it
  if(!lob_get(handshake,"type")) lob_set(handshake,"type","link"); // default to link type
  if(!lob_get_uint(handshake,"at")) lob_set_uint(handshake,"at",now); // require an at
  LOG("handshake at %d id %s",now,lob_get(handshake,"id"));
  
  // validate/extend link handshakes immediately
  if(util_cmp(lob_get(handshake,"type"),"link") == 0)
  {
    // get the csid
    uint8_t csid = 0;
    lob_t outer;
    if((outer = lob_linked(handshake)))
    {
      csid = outer->head[0];
    }else if(lob_get(handshake,"csid")){
      util_unhex(lob_get(handshake,"csid"),2,&csid);
    }
    if(!csid)
    {
      LOG("bad link handshake, no csid: %s",lob_json(handshake));
      lob_free(handshake);
      return NULL;
    }
    char hexid[3] = {0};
    util_hex(&csid, 1, hexid);
      
    // get attached hashname
    lob_t tmp = lob_parse(handshake->body, handshake->body_len);
    from = hashname_vkey(tmp, csid);
    if(!from)
    {
      LOG("bad link handshake, no hashname: %s",lob_json(handshake));
      lob_free(tmp);
      lob_free(handshake);
      return NULL;
    }
    lob_set(handshake,"csid",hexid);
    lob_set(handshake,"hashname",hashname_char(from));
    lob_set_raw(handshake,hexid,2,"true",4); // intermediate format
    lob_body(handshake, tmp->body, tmp->body_len); // re-attach as raw key
    lob_free(tmp);

    // short-cut, if it's a key from an existing link, pass it on
    // TODO: using mesh_linked here is a stack issue during loopback peer test!
    if((link = mesh_linkid(mesh,from))) return link_receive_handshake(link, handshake);
    LOG("no link found for handshake from %s",hashname_char(from));

    // extend the key json to make it compatible w/ normal patterns
    tmp = lob_new();
    lob_set_base32(tmp,hexid,handshake->body,handshake->body_len);
    lob_set_raw(handshake,"keys",0,(char*)tmp->head,tmp->head_len);
    lob_free(tmp);
  }

  // tell anyone listening about the newly discovered handshake
  mesh_discover(mesh, handshake);
  
  return from == NULL ? NULL : mesh_linkid(mesh, from);
}

// processes incoming packet, it will take ownership of outer
link_t mesh_receive(mesh_t mesh, lob_t outer)
{
  lob_t inner = NULL;
  link_t link = NULL;
  char token[17] = {0};
  hashname_t id;

  if(!mesh || !outer) return LOG("bad args");
  
  LOG("mesh receiving %s to %s",outer->head_len?"handshake":"channel",hashname_short(mesh->id));

  // redirect modern routed packets
  if(outer->head_len == 5)
  {
    id = hashname_sbin(outer->head);
    link = mesh_linkid(mesh, id);
    if(!link)
    {
      LOG_WARN("unknown id for route request: %s",hashname_short(id));
      lob_free(outer);
      return NULL;
    }

    lob_t outer2 = lob_parse(outer->body,outer->body_len);
    lob_free(outer);
    LOG_INFO("route forwarding to %s len %d",hashname_short(link->id),lob_len(outer2));
    link_send(link, outer2);
    return NULL; // don't know the sender
  }

  // process handshakes
  if(outer->head_len == 1)
  {
    inner = e3x_self_decrypt(mesh->self, outer);
    if(!inner)
    {
      LOG_WARN("%02x handshake failed %s",outer->head[0],e3x_err());
      lob_free(outer);
      return NULL;
    }
    
    // couple the two together, inner->outer
    lob_link(inner,outer);

    // set the unique id string based on some of the first 16 (routing token) bytes in the body
    base32_encode(outer->body,10,token,17);
    lob_set(inner,"id",token);

    // process the handshake
    return mesh_receive_handshake(mesh, inner);
  }

  // handle channel packets
  if(outer->head_len == 0)
  {
    if(outer->body_len < 16)
    {
      LOG("packet too small %d",outer->body_len);
      lob_free(outer);
      return NULL;
    }

    for(link = mesh->links;link;link = link->next) if(link->x && memcmp(link->x->token,outer->body,8) == 0) break;

    if(!link)
    {
      LOG("no link found for token %s",util_hex(outer->body,8,NULL));
      lob_free(outer);
      return NULL;
    }
    
    inner = e3x_exchange_receive(link->x, outer);
    lob_free(outer);
    if(!inner) return LOG("channel decryption fail for link %s %s",hashname_short(link->id),e3x_err());
    
    LOG("channel packet %d bytes from %s",lob_len(inner),hashname_short(link->id));
    return link_receive(link,inner);
    
  }

  // transform incoming bare link json format into handshake for discovery
  if((inner = lob_get_json(outer,"keys")))
  {
    if((id = hashname_vkeys(inner)))
    {
      lob_set(outer,"hashname",hashname_char(id));
      lob_set_int(outer,"at",0);
      lob_set(outer,"type","link");
      LOG("bare incoming link json being discovered %s",lob_json(outer));
    }
    lob_free(inner);
  }
  
  // run everything else through discovery, usually plain handshakes
  mesh_discover(mesh, outer);
  link = mesh_linked(mesh, lob_get(outer,"hashname"), 0);
  lob_free(outer);

  return link;
}
#include "telehash.h"
#include <string.h>
#include <stdlib.h>
#include "telehash.h"
#include "telehash.h"

link_t link_new(mesh_t mesh, hashname_t id)
{
  link_t link;

  if(!mesh || !id) return LOG("invalid args");

  LOG("adding link %s",hashname_short(id));
  if(!(link = malloc(sizeof (struct link_struct)))) return LOG("OOM");
  memset(link,0,sizeof (struct link_struct));
  
  link->id = hashname_dup(id);
  link->csid = 0x01; // default state
  link->mesh = mesh;
  link->next = mesh->links;
  mesh->links = link;

  return link;
}

void link_free(link_t link)
{
  if(!link) return;

  LOG("dropping link %s",hashname_short(link->id));
  mesh_t mesh = link->mesh;
  if(mesh->links == link)
  {
    mesh->links = link->next;
  }else{
    link_t li;
    for(li = mesh->links;li;li = li->next) if(li->next == link)
    {
      li->next = link->next;
    }
  }

  // drop
  if(link->x)
  {
    e3x_exchange_free(link->x);
    link->x = NULL;
  }

  // notify pipe w/ NULL packet
  if(link->send_cb) link->send_cb(link, NULL, link->send_arg);

  // go through link->chans
  chan_t c, cnext;
  for(c = link->chans;c;c = cnext)
  {
    cnext = chan_next(c);
    chan_free(c);
  }

  hashname_free(link->id);
  lob_free(link->key);
  free(link);
}

link_t link_get(mesh_t mesh, hashname_t id)
{
  link_t link;

  if(!mesh || !id) return LOG("invalid args");
  for(link = mesh->links;link;link = link->next) if(hashname_cmp(id,link->id) == 0) return link;
  return link_new(mesh,id);
}

// simple accessors
hashname_t link_id(link_t link)
{
  if(!link) return NULL;
  return link->id;
}

lob_t link_key(link_t link)
{
  if(!link) return NULL;
  return link->key;
}

// get existing channel id if any
chan_t link_chan_get(link_t link, uint32_t id)
{
  chan_t c;
  if(!link || !id) return NULL;
  for(c = link->chans;c;c = chan_next(c)) if(chan_id(c) == id) return c;
  return NULL;
}

// get link info json
lob_t link_json(link_t link)
{
  char hex[3];
  lob_t json;
  if(!link) return LOG("bad args");

  json = lob_new();
  lob_set(json,"hashname",hashname_char(link->id));
  lob_set(json,"csid",util_hex(&link->csid, 1, hex));
  lob_set_base32(json,"key",link->key->body,link->key->body_len);
//  paths = lob_array(mesh->paths);
//  lob_set_raw(json,"paths",0,(char*)paths->head,paths->head_len);
//  lob_free(paths);
  return json;
}

link_t link_get_keys(mesh_t mesh, lob_t keys)
{
  uint8_t csid;

  if(!mesh || !keys) return LOG("invalid args");
  csid = hashname_id(mesh->keys,keys);
  if(!csid) return LOG("no supported key");
  lob_t key = hashname_im(keys,csid);
  link_t ret = link_get_key(mesh, key, csid);
  lob_free(key);
  return ret;
}

link_t link_get_key(mesh_t mesh, lob_t key, uint8_t csid)
{
  link_t link;

  if(!mesh || !key) return LOG("invalid args");
  if(hashname_id(mesh->keys,key) > csid) return LOG("invalid csid");

  link = link_get(mesh, hashname_vkey(key, csid));
  if(!link) return LOG("invalid key");

  // load key if it's not yet
  if(!link->key) return link_load(link, csid, key);

  return link;
}

// load in the key to existing link
link_t link_load(link_t link, uint8_t csid, lob_t key)
{
  char hex[3];
  lob_t copy;

  if(!link || !csid || !key) return LOG("bad args");
  if(link->x)
  {
    link->csid = link->x->csid; // repair in case mesh_unlink was called, any better place?
    return link;
  }

  LOG("adding %x key to link %s",csid,hashname_short(link->id));
  
  // key must be bin
  if(key->body_len)
  {
    copy = lob_new();
    lob_body(copy,key->body,key->body_len);
  }else{
    util_hex(&csid,1,hex);
    copy = lob_get_base32(key,hex);
  }
  link->x = e3x_exchange_new(link->mesh->self, csid, copy);
  if(!link->x)
  {
    LOG("invalid %x key %s %s",csid,util_hex(copy->body,copy->body_len,NULL),lob_json(key));
    lob_free(copy);
    return NULL;
  }

  link->csid = csid;
  link->key = copy;
  
  e3x_exchange_out(link->x, util_sys_seconds());
  LOG("new exchange session to %s",hashname_short(link->id));

  return link;
}

// add a delivery pipe to this link
link_t link_pipe(link_t link, link_t (*send)(link_t link, lob_t packet, void *arg), void *arg)
{
  if(!link || !send) return NULL;

  if(send == link->send_cb && arg == link->send_arg) return link; // noop
  if(link->send_cb) LOG_INFO("replacing existing pipe on link");

  link->send_cb = send;
  link->send_arg = arg;
  
  // flush handshake
  return link_sync(link);
}

// is the link ready/available
link_t link_up(link_t link)
{
  if(!link) return NULL;
  if(!link->x) return NULL;
  if(!e3x_exchange_out(link->x,0)) return NULL;
  if(!e3x_exchange_in(link->x,0)) return NULL;
  return link;
}

// process an incoming handshake
link_t link_receive_handshake(link_t link, lob_t inner)
{
  uint32_t in, out, at, err;
  uint8_t csid = 0;
  lob_t outer = lob_linked(inner);

  if(!link || !inner || !outer) return LOG("bad args");

  // inner/link must be validated by caller already, we just load if missing
  if(!link->key)
  {
    util_unhex(lob_get(inner, "csid"), 2, &csid);
    if(!link_load(link, csid, inner))
    {
      lob_free(inner);
      return LOG("load key failed for %s %u %s",hashname_short(link->id),csid,util_hex(inner->body,inner->body_len,NULL));
    }
  }

  if((err = e3x_exchange_verify(link->x,outer)))
  {
    lob_free(inner);
    return LOG("handshake verification fail: %d",err);
  }

  in = e3x_exchange_in(link->x,0);
  out = e3x_exchange_out(link->x,0);
  at = lob_get_uint(inner,"at");
  link_t ready = link_up(link);

  // if bad at, always send current handshake
  if(e3x_exchange_in(link->x, at) < out)
  {
    LOG("old handshake: %s (%d,%d,%d)",lob_json(inner),at,in,out);
    link_sync(link);
    lob_free(inner);
    return link;
  }

  // try to sync ephemeral key
  if(!e3x_exchange_sync(link->x,outer))
  {
    lob_free(inner);
    return LOG("sync failed");
  }
  
  // we may need to re-sync
  if(out != e3x_exchange_out(link->x,0)) link_sync(link);
  
  // notify of ready state change
  if(!ready && link_up(link))
  {
    LOG("link ready");
    mesh_link(link->mesh, link);
  }
  
  lob_free(inner);
  return link;
}

// process a decrypted channel packet
link_t link_receive(link_t link, lob_t inner)
{
  chan_t c;

  if(!link || !inner) return LOG("bad args");

  // see if existing channel and send there
  if((c = link_chan_get(link, lob_get_int(inner,"c"))))
  {
    LOG("\t<-- %s",lob_json(inner));
    // consume inner
    chan_receive(c, inner);
    // process any changes
    chan_process(c, 0);
    return link;
  }

  // if it's an open, validate and fire event
  if(!lob_get(inner,"type"))
  {
    LOG("invalid channel open, no type %s",lob_json(inner));
    lob_free(inner);
    return NULL;
  }
  if(!e3x_exchange_cid(link->x, inner))
  {
    LOG("invalid channel open id %s",lob_json(inner));
    lob_free(inner);
    return NULL;
  }
  inner = mesh_open(link->mesh,link,inner);
  if(inner)
  {
    LOG("unhandled channel open %s",lob_json(inner));
    lob_free(inner);
    return NULL;
  }
  
  return link;
}

// deliver this packet
link_t link_send(link_t link, lob_t outer)
{
  if(!outer) return LOG_INFO("send packet missing");
  if(!link || !link->send_cb)
  {
    lob_free(outer);
    return LOG_WARN("no network");
  }
  
  if(!link->send_cb(link, outer, link->send_arg))
  {
    lob_free(outer);
    return LOG_WARN("delivery failed");
  }

  return link;
}

lob_t link_handshake(link_t link)
{
  if(!link) return NULL;
  if(!link->x) return LOG_DEBUG("no exchange");
  
  LOG_DEBUG("generating a new handshake in %lu out %lu",link->x->in,link->x->out);
  lob_t handshake = lob_new();
  lob_t tmp = hashname_im(link->mesh->keys, link->csid);
  lob_body(handshake, lob_raw(tmp), lob_len(tmp));
  lob_free(tmp);
  
  // encrypt it
  tmp = handshake;
  handshake = e3x_exchange_handshake(link->x, tmp);
  lob_free(tmp);

  return handshake;
}

// send current handshake
link_t link_sync(link_t link)
{
  if(!link) return LOG("bad args");
  if(!link->x) return LOG("no exchange");
  if(!link->send_cb) return LOG("no network");

  return link_send(link, link_handshake(link));
}

// trigger a new exchange sync
link_t link_resync(link_t link)
{
  if(!link) return LOG("bad args");
  if(!link->x) return LOG("no exchange");

  // force a higher at, triggers all to sync
  e3x_exchange_out(link->x,e3x_exchange_out(link->x,0)+1);
  return link_sync(link);
}

// create/track a new channel for this open
chan_t link_chan(link_t link, lob_t open)
{
  chan_t c;
  if(!link || !open) return LOG("bad args");

  // add an outgoing cid if none set
  if(!lob_get_int(open,"c")) lob_set_uint(open,"c",e3x_exchange_cid(link->x, NULL));
  c = chan_new(open);
  if(!c) return LOG("invalid open %s",lob_json(open));
  LOG("new outgoing channel %d open: %s",chan_id(c), lob_get(open,"type"));

  c->link = link;
  c->next = link->chans;
  link->chans = c;

  return c;
}

// encrypt and send this one packet on this pipe
link_t link_direct(link_t link, lob_t inner)
{
  if(!link || !inner) return LOG("bad args");
  if(!link->send_cb)
  {
    LOG_WARN("no network, dropping %s",lob_json(inner));
    return NULL;
  }

  // add an outgoing cid if none set
  if(!lob_get_int(inner,"c")) lob_set_uint(inner,"c",e3x_exchange_cid(link->x, NULL));

  lob_t outer = e3x_exchange_send(link->x, inner);
  lob_free(inner);

  return link_send(link, outer);
}

// force link down, end channels and generate all events
link_t link_down(link_t link)
{
  if(!link) return NULL;

  LOG("forcing link down for %s",hashname_short(link->id));

  // generate down event if up
  if(link_up(link))
  {
    e3x_exchange_down(link->x);
    mesh_link(link->mesh, link);
  }

  // end all channels
  chan_t c, cnext;
  for(c = link->chans;c;c = cnext)
  {
    cnext = chan_next(c);
    chan_err(c, "disconnected");
    chan_process(c, 0);
  }

  // remove pipe
  if(link->send_cb)
  {
    link->send_cb(link, NULL, link->send_arg); // notify jic
    link->send_cb = NULL;
    link->send_arg = NULL;
  }

  return NULL;
}

// recursive to handle deletes
chan_t link_process_chan(chan_t c, uint32_t now)
{
  if(!c) return NULL;
  chan_t next = link_process_chan(chan_next(c), now);
  if(!chan_process(c, now)) return next;
  c->next = next;
  return c;
}

// process any channel timeouts based on the current/given time
link_t link_process(link_t link, uint32_t now)
{
  if(!link || !now) return LOG("bad args");
  link->chans = link_process_chan(link->chans, now);
  if(link->csid) return link;
  
  // flagged to remove, do that now
  link_down(link);
  link_free(link);
  return NULL;
}
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include "telehash.h"

// open must be chan_receive or chan_send next yet
chan_t chan_new(lob_t open)
{
  uint32_t id;
  char *type;
  chan_t c;

  if(!open) return LOG("open packet required");
  id = (uint32_t)lob_get_int(open,"c");
  if(!id) return LOG("invalid channel id");
  type = lob_get(open,"type");
  if(!type) return LOG("missing channel type");

  c = malloc(sizeof (struct chan_struct));
  memset(c,0,sizeof (struct chan_struct));
  c->state = CHAN_OPENING;
  c->id = id;
  c->type = lob_get(open,"type");

  LOG("new channel %d %s",id,type);
  return c;
}

chan_t chan_free(chan_t c)
{
  if(!c) return NULL;

  // gotta tell handler (TODO, still buggy)
  if(0 && c->state != CHAN_ENDED && c->handle)
  {
    chan_err(c, "closed");
    c->handle(c, c->arg);
  }

  // free any other queued packets
  lob_freeall(c->in);
  free(c);
  return NULL;
}

// return the numeric per-exchange id
uint32_t chan_id(chan_t c)
{
  if(!c) return 0;
  return c->id;
}

// this will set the default inactivity timeout using this event timer and our uid
uint32_t chan_timeout(chan_t c, uint32_t at)
{
  if(!c) return 0;

  // no timeout, just return how much time is left
  if(!at) return c->timeout;

  c->timeout = at;
  return c->timeout;
}

chan_t chan_next(chan_t c)
{
  if(!c) return NULL;
  return c->next;
}

enum chan_states chan_state(chan_t c)
{
  if(!c) return CHAN_ENDED;
  return c->state;
}

// incoming packets

// process into receiving queue
chan_t chan_receive(chan_t c, lob_t inner)
{
  if(!c || !inner) return LOG("bad args");
  
  c->in = lob_push(c->in, inner);
  return c;
}

// false to force start timers (any new handshake), true to cancel and resend last packet (after any e3x_sync)
chan_t chan_sync(chan_t c, uint8_t sync)
{
  if(!c) return NULL;
  LOG("%d sync %d TODO",c->id,sync);
  return c;
}

// get next avail packet in order, null if nothing
lob_t chan_receiving(chan_t c)
{
  lob_t ret;
  if(!c || !c->in) return NULL;

  ret = lob_shift(c->in);
  c->in = ret->next;
  ret->next = NULL;

  if(lob_get(ret,"end")) c->state = CHAN_ENDED;

  return ret;
}

// outgoing packets

// ack/miss only base packet
lob_t chan_oob(chan_t c)
{
  if(!c) return NULL;

  lob_t ret = lob_new();
  lob_set_uint(ret,"c",c->id);
  
  return ret;
}

// creates a packet w/ necessary json, best way to get valid packet for this channel
lob_t chan_packet(chan_t c)
{
  lob_t ret;
  if(!c) return NULL;
  
  ret = chan_oob(c);

  return ret;
}

// adds to sending queue, expects valid packet
chan_t chan_send(chan_t c, lob_t inner)
{
  if(!c || !inner) return LOG("bad args");
  
  LOG("channel send %d %s",c->id,lob_json(inner));
  if(!c->link)
  {
    lob_free(inner);
    return LOG("dropping packet, no link");
  }

  link_send(c->link, e3x_exchange_send(c->link->x, inner));

  lob_free(inner);

  return c;
}

// generates local-only error packet for next chan_process()
chan_t chan_err(chan_t c, char *msg)
{
  if(!c) return NULL;
  if(!msg) msg = "unknown";
  lob_t err = lob_new();
  lob_set_uint(err,"c",c->id);
  lob_set_raw(err, "end", 3, "true", 4);
  lob_set(err, "err", msg);
  c->in = lob_push(c->in, err); // top of the queue
  return c;
}

// must be called after every send or receive, processes resends/timeouts, fires handlers
chan_t chan_process(chan_t c, uint32_t now)
{
  if(!c) return NULL;

  // do timeout checks
  if(now)
  {
    if(c->timeout)
    {
      // trigger error
      if(now > c->timeout)
      {
        c->timeout = 0;
        chan_err(c, "timeout");
      }else if(c->trecv){
        // kick forward when we have a time difference
        c->timeout += (now - c->trecv);
      }
    }
    c->trecv = now;
  }
  
  // fire receiving handlers
  if(c->in && c->handle) c->handle(c, c->arg);

  if(c->state == CHAN_ENDED)
  {
    LOG("channel is now ended, freeing it");
    c = chan_free(c);
  }
  
  return c;
}

// size (in bytes) of buffered data in or out
uint32_t chan_size(chan_t c)
{
  uint32_t size = 0;
  lob_t cur;
  if(!c) return 0;

  // add up the sizes of the in and out buffers
  cur = c->in;
  while(cur)
  {
    size += lob_len(cur);
    cur = cur->next;
  }

  return size;
}

// set up internal handler for all incoming packets on this channel
chan_t chan_handle(chan_t c, void (*handle)(chan_t c, void *arg), void *arg)
{
  if(!c) return LOG("bad args");

  c->handle = handle;
  c->arg = arg;

  return c;
}
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "telehash.h"

char *util_hex(uint8_t *in, size_t len, char *out)
{
    uint32_t j;
    char *c = out;
    static char *hex = "0123456789abcdef";
    static char *buf = NULL;
    if(!in || !len) return NULL;

    // utility mode only! use/return an internal buffer
    if(!out && !(c = out = buf = realloc(buf,len*2+1))) return NULL;

    for (j = 0; j < len; j++) {
      *c = hex[((in[j]&240)/16)];
      c++;
      *c = hex[in[j]&15];
      c++;
    }
    *c = '\0';
    return out;
}

char hexcode(char x)
{
    if (x >= '0' && x <= '9')         /* 0-9 is offset by hex 30 */
      return (x - 0x30);
    else if (x >= 'A' && x <= 'F')    /* A-F offset by hex 37 */
      return(x - 0x37);
    else if (x >= 'a' && x <= 'f')    /* a-f offset by hex 37 */
      return(x - 0x57);
    else {                            /* Otherwise, an illegal hex digit */
      return x;
    }
}

uint8_t *util_unhex(char *in, size_t len, uint8_t *out)
{
  uint32_t j;
  uint8_t *c = out;
  if(!out || !in) return NULL;
  if(!len) len = strlen(in);

  for(j=0; (j+1)<len; j+=2)
  {
    *c = ((hexcode(in[j]) * 16) & 0xF0) + (hexcode(in[j+1]) & 0xF);
    c++;
  }
  return out;
}

char *util_ishex(char *str, uint32_t len)
{
  uint32_t i;
  for(i=0;i<len;i++)
  {
    if(!str[i]) return NULL;
    if(str[i] == hexcode(str[i])) return NULL;
  }
  return str;
}

int util_cmp(char *a, char *b)
{
  if(!a || !b) return -1;
  if(a == b) return 0;
  if(strlen(a) != strlen(b)) return -1;
  return util_ct_memcmp(a,b,strlen(a));
}

// default alpha sort
int _util_sort_alpha(void *arg, const void *a, const void *b)
{
  char *aa = *(char**)a;
  char *bb = *(char**)b;
  if(!aa) return -1;
  if(!bb) return 1;
  return strcmp(aa,bb);
}

// from http://git.uclibc.org/uClibc/tree/libc/stdlib/stdlib.c?id=515d54433138596e81267237542bd9168b8cc787#n789
/* This code is derived from a public domain shell sort routine by
 * Ray Gardner and found in Bob Stout's snippets collection. */

void util_sort(void *base, unsigned int nel, unsigned int width, int (*comp)(void *, const void *, const void *), void *arg)
{
  unsigned int wgap, i, j, k;
  char tmp;

  // added this for default alpha sort
  if(!comp) comp = _util_sort_alpha;

  if ((nel > 1) && (width > 0)) {
    wgap = 0;
    do {
      wgap = 3 * wgap + 1;
    } while (wgap < (nel-1)/3);
    /* From the above, we know that either wgap == 1 < nel or */
    /* ((wgap-1)/3 < (int) ((nel-1)/3) <= (nel-1)/3 ==> wgap <  nel. */
    wgap *= width;			/* So this can not overflow if wnel doesn't. */
    nel *= width;			/* Convert nel to 'wnel' */
    do {
      i = wgap;
      do {
        j = i;
        do {
          register char *a;
          register char *b;

          j -= wgap;
          a = j + ((char *)base);
          b = a + wgap;
          if ((*comp)(arg, a, b) <= 0) {
            break;
          }
          k = width;
          do {
            tmp = *a;
            *a++ = *b;
            *b++ = tmp;
          } while (--k);
        } while (j >= wgap);
        i += width;
      } while (i < nel);
      wgap = (wgap - width)/3;
    } while (wgap);
  }
}

// portable friendly reallocf
void *util_reallocf(void *ptr, size_t size)
{
  void *ra;
  // zero == free
  if(!size)
  {
    if(ptr) free(ptr);
    return NULL;
  }
  ra = realloc(ptr,size);
  if(ra) return ra;
  free(ptr);
  return NULL;
}

uint64_t util_at(void)
{
  uint64_t at;
  uint32_t *half = (uint32_t*)(&at);

  // store both current seconds and ms since then in one value
  half[0] = util_sys_seconds();
  half[1] = (uint32_t)util_sys_ms(half[0]);

  return at;
}

uint32_t util_since(uint64_t at)
{
  uint32_t *half = (uint32_t*)(&at);
  return ((uint32_t)util_sys_ms(half[0]) - half[1]);
}

int util_ct_memcmp(const void* s1, const void* s2, size_t n)
{
    const unsigned char *p1 = s1, *p2 = s2;
    int x = 0;

    while (n--)
    {
        x |= (*p1 ^ *p2);
        p1++;
        p2++;
    }

    /* Don't leak any info besides failure */
    if (x)
        x = 1;

    return x;
}

// embedded may not have strdup but it's a kinda handy shortcut
char *util_strdup(const char *str)
{
  char *ret;
  size_t len = 0;
  if(str) len = strlen(str);
  if(!(ret = malloc(len+1))) return NULL;
  memcpy(ret,str,len);
  ret[len] = 0;
  return ret;
}

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "telehash.h"

// one malloc per chunk, put storage after it
util_chunks_t util_chunk_new(util_chunks_t chunks, uint8_t len)
{
  util_chunk_t chunk;
  size_t size = sizeof (struct util_chunk_struct);
  size += len;
  if(!(chunk = malloc(size))) return LOG("OOM");
  memset(chunk,0,size);
  chunk->size = len;
  // point to extra space after struct, less opaque
//  chunk->data = ((void*)chunk)+(sizeof (struct util_chunk_struct));

  // add to reading list
  chunk->prev = chunks->reading;
  chunks->reading = chunk;
  chunks->readat = 0;

  return chunks;
}

util_chunk_t util_chunk_free(util_chunk_t chunk)
{
  if(!chunk) return NULL;
  util_chunk_t prev = chunk->prev;
  free(chunk);
  return util_chunk_free(prev);
}

util_chunks_t util_chunks_new(uint8_t size)
{
  util_chunks_t chunks;
  if(!(chunks = malloc(sizeof (struct util_chunks_struct)))) return LOG("OOM");
  memset(chunks,0,sizeof (struct util_chunks_struct));
  chunks->blocked = 0;
  chunks->blocking = 1; // default

  if(!size)
  {
    chunks->cap = 255;
  }else if(size == 1){
    chunks->cap = 1; // minimum
  }else{
    chunks->cap = size-1;
  }

  return chunks;
}

util_chunks_t util_chunks_free(util_chunks_t chunks)
{
  if(!chunks) return NULL;
  if(chunks->writing) lob_free(chunks->writing);
  util_chunk_free(chunks->reading);
  free(chunks);
  return NULL;
}

uint32_t util_chunks_writing(util_chunks_t chunks)
{
  lob_t cur;
  uint32_t len = 0;
  if(!chunks) return 0;
  util_chunks_len(chunks); // flushes
  len = lob_len(chunks->writing) - chunks->writeat;
  for(cur=lob_next(chunks->writing);cur;cur = lob_next(cur)) len += lob_len(cur);
  return len;
}

util_chunks_t util_chunks_send(util_chunks_t chunks, lob_t out)
{
  if(!chunks || !out) return LOG("bad args");
//  LOG("sending chunked packet len %d hash %d",lob_len(out),murmur4((uint32_t*)lob_raw(out),lob_len(out)));

  chunks->writing = lob_push(chunks->writing, out);
  return chunks;
}

// get any packets that have been reassembled from incoming chunks
lob_t util_chunks_receive(util_chunks_t chunks)
{
  util_chunk_t chunk, flush;
  size_t len = 0;

  if(!chunks || !chunks->reading) return NULL;
  
  // add up total length of any sequence
  for(flush = NULL,chunk = chunks->reading;chunk;chunk=chunk->prev)
  {
    // only start/reset on flush
    if(chunk->size == 0)
    {
      flush = chunk;
      len = 0;
    }
    if(flush) len += chunk->size;
//    LOG("chunk %d %d len %d next %d",chunk->size,chunks->cap,len,chunk->prev);
  }

  if(!flush) return NULL;
  
  // clip off before flush
  if(chunks->reading == flush)
  {
    chunks->reading = NULL;
  }else{
    for(chunk = chunks->reading;chunk->prev != flush;chunk = chunk->prev);
    chunk->prev = NULL;
  }
  
  // pop off empty flush
  chunk = flush->prev;
  free(flush);

  // if lone flush, just recurse
  if(!chunk) return util_chunks_receive(chunks);

  // TODO make a lob_new that creates space to prevent double-copy here
  uint8_t *buf = malloc(len);
  if(!buf) return LOG("OOM");
  
  // eat chunks copying in
  util_chunk_t prev;
  size_t at;
  for(at=len;chunk;chunk = prev)
  {
    prev = chunk->prev;
    // backfill since we're inverted
    memcpy(buf+(at-chunk->size),chunk->data,chunk->size);
    at -= chunk->size;
    free(chunk);
  }
  
  chunks->ack = 1; // make sure ack is set after any full packets too
//  LOG("parsing chunked packet length %d hash %d",len,murmur4((uint32_t*)buf,len));
  lob_t ret = lob_parse(buf,len);
  chunks->err = ret ? 0 : 1;
  free(buf);
  return ret;
}

// internal to append read data
util_chunks_t _util_chunks_append(util_chunks_t chunks, uint8_t *block, size_t len)
{
  if(!chunks || !block || !len) return chunks;
  uint8_t quota = 0;
  
  // first, determine if block is a new chunk or a remainder of a previous chunk (quota > 0)
  if(chunks->reading) quota = chunks->reading->size - chunks->readat;

//  LOG("chunks append %d q %d",len,quota);
  
  // no space means we're at a chunk start byte
  if(!quota)
  {
    if(!util_chunk_new(chunks,*block)) return LOG("OOM");
    // a chunk was received, unblock
    chunks->blocked = 0;
    // if it had data, flag to ack
    if(*block) chunks->ack = 1;
    // start processing the data now that there's space
    return _util_chunks_append(chunks,block+1,len-1);
  }

  // only a partial data avail now
  if(len < quota) quota = len;

  // copy in quota space and recurse
  memcpy(chunks->reading->data+chunks->readat,block,quota);
  chunks->readat += quota;
  return _util_chunks_append(chunks,block+quota,len-quota);
}

// how many bytes are there waiting
uint32_t util_chunks_len(util_chunks_t chunks)
{
  if(!chunks || chunks->blocked) return 0;

  // when no packet, only send an ack
  if(!chunks->writing) return (chunks->ack) ? 1 : 0;

  // what's the total left to write
  size_t avail = lob_len(chunks->writing) - chunks->writeat;

  // only deal w/ the next chunk
  if(avail > chunks->cap) avail = chunks->cap;
  if(!chunks->waiting) chunks->waiting = avail;

  // just writing the waiting size byte first
  if(!chunks->waitat) return 1;

  return chunks->waiting - (chunks->waitat-1);
}

// return the next block of data to be written to the stream transport
uint8_t *util_chunks_write(util_chunks_t chunks)
{
  // ensures consistency
  if(!util_chunks_len(chunks)) return NULL;
  
  // always write the chunk size byte first, is also the ack/flush
  if(!chunks->waitat) return &chunks->waiting;
  
  // into the raw data
  return lob_raw(chunks->writing)+chunks->writeat+(chunks->waitat-1);
}

// advance the write pointer this far
util_chunks_t util_chunks_written(util_chunks_t chunks, size_t len)
{
  if(!chunks || !len) return chunks;
  if(len > util_chunks_len(chunks)) return LOG("len too big %d > %d",len,util_chunks_len(chunks));
  chunks->waitat += len;
  chunks->ack = 0; // any write is an ack

//  LOG("chunks written %d at %d ing %d",len,chunks->waitat,chunks->waiting);

  // if a chunk was done, advance to next chunk
  if(chunks->waitat > chunks->waiting)
  {
    // confirm we wrote the chunk data and size
    chunks->writeat += chunks->waiting;
    chunks->waiting = chunks->waitat = 0;

    // only block if it was a full chunk
    if(chunks->waiting == chunks->cap) chunks->blocked = chunks->blocking;

    // only advance packet after we wrote a flushing 0
    if(len == 1 && chunks->writing && chunks->writeat == lob_len(chunks->writing))
    {
      lob_t old = lob_shift(chunks->writing);
      chunks->writing = old->next;
      old->next = NULL;
      lob_free(old);
      chunks->writeat = 0;
      // always block after a full packet
      chunks->blocked = chunks->blocking;
    }
  }
  
  return chunks;
}

// queues incoming stream based data
util_chunks_t util_chunks_read(util_chunks_t chunks, uint8_t *block, size_t len)
{
  if(!_util_chunks_append(chunks,block,len)) return NULL;
  if(!chunks->reading) return NULL; // paranoid
  return chunks;
}


////// these are for frame-based transport

// size of the next chunk, -1 when none, max is chunks size-1
int16_t util_chunks_size(util_chunks_t chunks)
{
  if(!util_chunks_len(chunks)) return -1;
  return chunks->waiting;
}

// return the next chunk of data, use util_chunks_next to advance
uint8_t *util_chunks_frame(util_chunks_t chunks)
{
  if(!chunks || !chunks->waiting) return NULL;
  // into the raw data
  return lob_raw(chunks->writing)+chunks->writeat;
  
}

// process incoming chunk
util_chunks_t util_chunks_chunk(util_chunks_t chunks, uint8_t *chunk, int16_t size)
{
  if(!chunks || size < 0) return NULL;
  if(!_util_chunks_append(chunks,(uint8_t*)&size,1)) return NULL;
  if(!_util_chunks_append(chunks,chunk,size)) return NULL;
  return chunks;
}

// peek into what the next chunk size will be, to see terminator ones
int16_t util_chunks_peek(util_chunks_t chunks)
{
  int16_t size = util_chunks_size(chunks);
  // TODO, peek into next chunk
  if(size <= 0) return -1;
  return lob_len(chunks->writing) - (chunks->writeat+size);
}

// advance the write past the current chunk
util_chunks_t util_chunks_next(util_chunks_t chunks)
{
  int16_t size = util_chunks_size(chunks);
  if(size < 0) return NULL;
  // header byte first, then full chunk
  if(!util_chunks_written(chunks,1)) return NULL;
  if(!util_chunks_written(chunks,size)) return NULL;
  return chunks;
}
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "telehash.h"

// max payload size per frame
#define PAYLOAD(f) (f->size - 4)

// one malloc per frame, put storage after it
util_frames_t util_frame_new(util_frames_t frames)
{
  util_frame_t frame;
  size_t size = sizeof (struct util_frame_struct);
  size += PAYLOAD(frames);
  if(!(frame = malloc(size))) return LOG_WARN("OOM");
  memset(frame,0,size);
  
  // add to inbox
  frame->prev = frames->cache;
  frames->cache = frame;
  frames->in++;

  return frames;
}

util_frame_t util_frame_free(util_frame_t frame)
{
  if(!frame) return NULL;
  util_frame_t prev = frame->prev;
  free(frame);
  return util_frame_free(prev);
}

util_frames_t util_frames_clear(util_frames_t frames)
{
  if(!frames) return NULL;
  frames->err = 0;
  frames->inbase = frames->outbase = 42;
  frames->in = frames->out = 0;
  frames->cache = util_frame_free(frames->cache);
  frames->flush = 1; // always force a flush after a clear to let the other party know
  return frames;
}

util_frames_t util_frames_new(uint8_t size)
{
  if(size < 16 || size > 128) return LOG_ERROR("invalid size: %u",size);

  util_frames_t frames;
  if(!(frames = malloc(sizeof (struct util_frames_struct)))) return LOG_WARN("OOM");
  memset(frames,0,sizeof (struct util_frames_struct));
  frames->size = size;

  // default init hash state
  util_frames_clear(frames);
  frames->flush = 0; // don't start w/ a flush
  return frames;
}

util_frames_t util_frames_free(util_frames_t frames)
{
  if(!frames) return NULL;
  lob_freeall(frames->inbox);
  lob_freeall(frames->outbox);
  util_frame_free(frames->cache);
  free(frames);
  return NULL;
}

util_frames_t util_frames_ok(util_frames_t frames)
{
  if(frames && !frames->err) return frames;
  return NULL;
}

util_frames_t util_frames_send(util_frames_t frames, lob_t out)
{
  if(!frames) return LOG_WARN("bad args");
  if(frames->err) return LOG_WARN("frame state error");
  
  if(out)
  {
    out->id = 0; // used to track sent bytes
    frames->outbox = lob_push(frames->outbox, out);
  }else{
    frames->flush = 1;
  }

  return frames;
}

// get any packets that have been reassembled from incoming frames
lob_t util_frames_receive(util_frames_t frames)
{
  if(!frames || !frames->inbox) return NULL;
  lob_t pkt = lob_shift(frames->inbox);
  frames->inbox = pkt->next;
  pkt->next = NULL;
  return pkt;
}

void frames_lob(util_frames_t frames, uint8_t *tail, uint8_t len)
{  
}

// total bytes in the inbox/outbox
size_t util_frames_inlen(util_frames_t frames)
{
  if(!frames) return 0;

  size_t len = 0;
  lob_t cur = frames->inbox;
  do {
    len += lob_len(cur);
    cur = lob_next(cur);
  }while(cur);
  
  // add cached frames
  len += (frames->in * PAYLOAD(frames));
  
  return len;
}

size_t util_frames_outlen(util_frames_t frames)
{
  if(!frames) return 0;
  size_t len = 0;
  lob_t cur = frames->outbox;
  do {
    len += lob_len(cur);
    cur = lob_next(cur);
  }while(cur);
  
  // subtract sent
  if(frames->outbox) len -= frames->outbox->id;
  
  return len;
}

// is just a check to see if there's data waiting to be sent
util_frames_t util_frames_waiting(util_frames_t frames)
{
  if(!frames) return NULL;
  if(frames->err) return LOG_WARN("frame state error");
  
  if(frames->flush) return frames;
  if(frames->outbox) return frames;
  return NULL;
}

// is there an expectation of an incoming frame
util_frames_t util_frames_await(util_frames_t frames)
{
  if(!frames) return NULL;
  if(frames->err) return LOG_WARN("frame state error");
  // need more to complete inbox
  if(frames->cache) return frames;
  // outbox is complete, awaiting flush
  if((frames->out * PAYLOAD(frames)) > lob_len(frames->outbox)) return frames;
  return NULL;
}

// is a frame pending to be sent immediately
util_frames_t util_frames_pending(util_frames_t frames)
{
  if(!frames) return LOG_WARN("bad args");
  if(frames->err) return LOG_WARN("frame state error");
  
  if(frames->flush) return frames;

  uint8_t size = PAYLOAD(frames);
  uint32_t len = lob_len(frames->outbox); 
  if(len && (frames->out * size) <= len)
  {
    LOG_CRAZY("data pending %lu/%lu",len,(frames->out * size));
    return frames;
  }
  
  return NULL;
}

// the next frame of data in/out, if data NULL bool is just ready check
util_frames_t util_frames_inbox(util_frames_t frames, uint8_t *data, uint8_t *meta)
{
  if(!frames) return LOG_WARN("bad args");
  if(frames->err) return LOG_WARN("frame state error");
  if(!data) return util_frames_await(frames);
  
  // conveniences for code readability
  uint8_t size = PAYLOAD(frames);
  uint32_t hash1;
  memcpy(&(hash1),data+size,4);
  uint32_t hash2 = murmur4(data,size);
  uint32_t inlast = (frames->cache)?frames->cache->hash:frames->inbase;
  
//  LOG("frame sz %u hash rx %lu check %lu",size,hash1,hash2);
  
  // meta frames are self contained
  if(hash1 == hash2)
  {
//    LOG("meta frame %s",util_hex(data,size+4,NULL));

    // if requested, copy in metadata block
    if(meta) memcpy(meta,data+10,size-10);

    // verify sender's last rx'd hash
    uint32_t rxd;
    memcpy(&rxd,data,4);
    uint8_t *bin = lob_raw(frames->outbox);
    uint32_t len = lob_len(frames->outbox);
    uint32_t rxs = frames->outbase;
    uint8_t next = 0;
    do {
      // here next is always the frame to be re-sent, rxs is always the previous frame
      if(rxd == rxs)
      {
        frames->out = next;
        break;
      }

      // handle tail hash correctly like sender
      uint32_t at = next * size;
      rxs ^= murmur4((bin+at), ((at+size) > len) ? (len - at) : size);
      rxs += next;
      if(len < size) break;
    }while((next*size) < len && ++next);

    // it must have matched something above
    if(rxd != rxs)
    {
      LOG_WARN("invalid received frame hash %lu check %lu",rxd,rxs);
      frames->err = 1;
      return NULL;
    }
    
    // advance full packet once confirmed
    if((frames->out * size) > len)
    {
      frames->out = 0;
      frames->outbase = rxd;
      lob_t done = lob_shift(frames->outbox);
      frames->outbox = done->next;
      done->next = NULL;
      lob_free(done);
    }

    // sender's last tx'd hash mismatch causes flush
    memcpy(&rxd,data+4,4);
    if(rxd != inlast)
    {
      frames->flush = 1;
      LOG_DEBUG("flushing mismatch, hash %lu last %lu",rxd,inlast);
    }
    
    return frames;
  }
  
  // dedup, ignore if identical to any received one
  if(hash1 == frames->inbase) return frames;
  util_frame_t cache = frames->cache;
  for(;cache;cache = cache->prev) if(cache->hash == hash1) return frames;

  // full data frames must match combined w/ previous
  hash2 ^= inlast;
  hash2 += frames->in;
  if(hash1 == hash2)
  {
    if(!util_frame_new(frames)) return LOG_WARN("OOM");
    // append, update inlast, continue
    memcpy(frames->cache->data,data,size);
    frames->cache->hash = hash1;
    frames->flush = 0;
//    LOG("got data frame %lu",hash1);
    return frames;
  }
  
  // check if it's a tail data frame
  uint8_t tail = data[size-1];
  if(tail >= size)
  {
    frames->flush = 1;
    return LOG_DEBUG("invalid frame %u tail %u >= %u hash %lu/%lu base %lu last %lu",frames->in,tail,size,hash1,hash2,frames->inbase,inlast);
  }
  
  // hash must match
  hash2 = murmur4(data,tail);
  hash2 ^= inlast;
  hash2 += frames->in;
  if(hash1 != hash2)
  {
    frames->flush = 1;
    return LOG_DEBUG("invalid frame %u tail %u hash %lu != %lu base %lu last %lu",frames->in,tail,hash1,hash2,frames->inbase,inlast);
  }
  
  // process full packet w/ tail, update inlast, set flush
//  LOG("got frame tail of %u",tail);
  frames->flush = 1;
  frames->inbase = hash1;

  size_t tlen = (frames->in * size) + tail;

  // TODO make a lob_new that creates space to prevent double-copy here
  uint8_t *buf = malloc(tlen);
  if(!buf) return LOG_WARN("OOM");
  
  // copy in tail
  memcpy(buf+(frames->in * size), data, tail);
  
  // eat cached frames copying in reverse
  util_frame_t frame = frames->cache;
  while(frames->in && frame)
  {
    frames->in--;
    memcpy(buf+(frames->in*size),frame->data,size);
    frame = frame->prev;
  }
  frames->cache = util_frame_free(frames->cache);
  
  lob_t packet = lob_parse(buf,tlen);
  if(!packet) LOG_WARN("packet parsing failed: %s",util_hex(buf,tlen,NULL));
  free(buf);
  frames->inbox = lob_push(frames->inbox,packet);
  return frames;
}

util_frames_t util_frames_outbox(util_frames_t frames, uint8_t *data, uint8_t *meta)
{
  if(!frames) return LOG_WARN("bad args");
  if(frames->err) return LOG_WARN("frame state error");
  if(!data) return util_frames_waiting(frames); // just a ready check
  uint8_t size = PAYLOAD(frames);
  uint8_t *out = lob_raw(frames->outbox);
  uint32_t len = lob_len(frames->outbox); 
  
  // clear/init
  uint32_t hash = frames->outbase;
  
  // first get the last sent hash
  if(len)
  {
    // safely only hash the packet size correctly
    uint32_t at, i;
    for(i = at = 0;at < len && i < frames->out;i++,at += size)
    {
      hash ^= murmur4((out+at), ((at - len) < size) ? (at - len) : size);
      hash += i;
    }
  }

  // if flushing, or nothing to send, just send meta frame w/ hashes
  if(frames->flush || !len || (frames->out * size) > len)
  {
    frames->flush = 1; // so _sent() does us proper
    memset(data,0,size+4);
    uint32_t inlast = (frames->cache)?frames->cache->hash:frames->inbase;
    memcpy(data,&(inlast),4);
    memcpy(data+4,&(hash),4);
    if(meta) memcpy(data+10,meta,size-10);
    murmur(data,size,data+size);
    LOG_CRAZY("sending meta frame inlast %lu cur %lu",inlast,hash);
    return frames;
  }
  
  // send next frame
  memset(data,0,size+4);
  uint32_t at = frames->out * size;
  if((at + size) > len)
  {
    size = len - at;
    data[PAYLOAD(frames)-1] = size;
  }
  memcpy(data,out+at,size);
  hash ^= murmur4(data,size);
  hash += frames->out;
  memcpy(data+PAYLOAD(frames),&(hash),4);
  LOG_CRAZY("sending data frame %u %lu",frames->out,hash);

  return frames;
}

// out state changes, returns if more to send
util_frames_t util_frames_sent(util_frames_t frames)
{
  if(!frames) return LOG_WARN("bad args");
  if(frames->err) return LOG_WARN("frame state error");
  uint8_t size = PAYLOAD(frames);
  uint32_t len = lob_len(frames->outbox); 
  uint32_t at = frames->out * size;

  // we sent a meta-frame, clear flush and done
  if(frames->flush || !len || at > len)
  {
    frames->flush = 0;
    return NULL;
  }

  // else advance payload
  if((at + size) > len) size = len - at;
  frames->outbox->id = at + size; // track exact sent bytes
  frames->out++; // advance sent frames counter

  // if no more, signal done
  if((frames->out * size) > len) return NULL;
  
  // more to go
  return frames;
}

// busy check, in or out
util_frames_t util_frames_busy(util_frames_t frames)
{
  if(!frames) return NULL;
  if(util_frames_waiting(frames)) return frames;
  return util_frames_await(frames);
}

#if !defined(_WIN32) && (defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__)))

#include <stdio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include "telehash.h"

#include "telehash.h"

lob_t util_fjson(char *file)
{
  unsigned char *buf;
  size_t len;
  struct stat fs;
  FILE *fd;
  lob_t p;
  
  fd = fopen(file,"rb");
  if(!fd) return LOG("fopen error %s: %s",file,strerror(errno));
  if(fstat(fileno(fd),&fs) < 0)
  {
    fclose(fd);
    return LOG("fstat error %s: %s",file,strerror(errno));
  }
  
  if(!(buf = malloc((size_t)fs.st_size)))
  {
    fclose(fd);
    return LOG("OOM");
  }
  len = fread(buf,1,(size_t)fs.st_size,fd);
  fclose(fd);
  if(len != (size_t)fs.st_size)
  {
    free(buf);
    return LOG("fread %d != %d for %s: %s",len,fs.st_size,file,strerror(errno));
  }
  
  p = lob_new();
  lob_head(p, buf, len);
  if(!p) LOG("json failed %s parsing %.*s",file,len,buf);
  free(buf);
  return p;
}

mesh_t util_links(mesh_t mesh, char *file)
{
  lob_t links = util_fjson(file);
  if(!links) return NULL;

  // TODO iterate and link

  lob_free(links);

  return mesh;
}

int util_sock_timeout(int sock, uint32_t ms)
{
  struct timeval tv;

  tv.tv_sec = ms/1000;
  tv.tv_usec = (ms%1000)*1000;

  if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
  {
    LOG("timeout setsockopt error %s",strerror(errno));
    return -1;
  }

  return sock;
}

#endif
#if !defined(_WIN32) && (defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__)))

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "telehash.h"

at_t util_sys_seconds()
{
  return (at_t)time(0);
}

unsigned long long util_sys_ms(long epoch)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  if(epoch > tv.tv_sec) return 0;
  return (unsigned long long)(tv.tv_sec - epoch) * 1000 + (unsigned long long)(tv.tv_usec) / 1000;
}

unsigned short util_sys_short(unsigned short x)
{
  return ntohs(x);
}

unsigned long util_sys_long(unsigned long x)
{
  return ntohl(x);
}

void util_sys_random_init(void)
{
  struct timeval tv;
  unsigned int seed;

  // TODO ifdef for srandomdev when avail
  gettimeofday(&tv, NULL);
  seed = ((unsigned int)getpid() << 16) ^ (unsigned int)tv.tv_sec ^ (unsigned int)tv.tv_usec;
  srandom(seed);
}

long util_sys_random(void)
{
  // TODO, use ifdef for arc4random
  return random();
}

#ifdef DEBUG
static int _logging = 1;
#else
static int _logging = 0;
#endif

void util_sys_logging(int enabled)
{
  if(enabled < 0)
  {
    _logging ^= 1;
  }else{
    _logging = enabled;    
  }
  LOG("log output enabled");
}

void *util_sys_log(uint8_t level, const char *file, int line, const char *function, const char * format, ...)
{
  char buffer[256];
  va_list args;
  if(!_logging) return NULL;
  // https://en.wikipedia.org/wiki/Syslog#Severity_level
  char *lstr = NULL;
  switch(level)
  {
    case 0: lstr = "EMERG  "; break;
    case 1: lstr = "ALERT  "; break;
    case 2: lstr = "CRIT   "; break;
    case 3: lstr = "ERROR  "; break;
    case 4: lstr = "WARN   "; break;
    case 5: lstr = "NOTICE "; break;
    case 6: lstr = "INFO   "; break;
    case 7: lstr = "DEBUG  "; break;
    case 8: lstr = "CRAZY  "; break;
    default: lstr = "?????? "; break;
  }
  va_start (args, format);
  vsnprintf (buffer, 256, format, args);
  fprintf(stderr,"%s%s:%d %s() %s\n",lstr,file, line, function, buffer);
  fflush(stderr);
  va_end (args);
  return NULL;
}

#endif
#include "telehash.h"

e3x_cipher_t cs2a_init(lob_t options)
{
  return NULL;
}
#include "telehash.h"

e3x_cipher_t cs3a_init(lob_t options)
{
  return NULL;
}
