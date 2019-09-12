/*
 * src/tutorial/email.c
 */
#include "postgres.h"
#include "utils/builtins.h"
#include "fmgr.h"
#include "access/hash.h"
#include "catalog/pg_collation.h"
#include <ctype.h>
#include <string.h>


PG_MODULE_MAGIC;

#define MAX_DOMAIN_LEN 256
#define MAX_LOCAL_LEN 256
#define MAX_EMAIL_LEN MAX_DOMAIN_LEN + MAX_LOCAL_LEN + 1

typedef struct {
  char v1_len_[4];
  int32 at_pos;
  char addr[1];
} EmailAddr;

Datum emailaddr_in(PG_FUNCTION_ARGS);
Datum emailaddr_out(PG_FUNCTION_ARGS);

int dom_check(char *str, int32 at_pos);
int loc_check(char *str, int32 at_pos);

/*****************************************************************************
 * Input/Output functions
 *****************************************************************************/

PG_FUNCTION_INFO_V1(emailaddr_in);

Datum emailaddr_in(PG_FUNCTION_ARGS) {
  char *str = PG_GETARG_CSTRING(0);
  EmailAddr *result;
  int32 i = 0;
  int32 input_len = strlen(str);
  int32 at_num = 0;
  int32 at_pos = 0;
  /* Check input length. */
  if (input_len > MAX_EMAIL_LEN) {
    ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                    errmsg("invalid input syntax for emailaddr: \"%s\"", str)));
  }
  char t1[input_len + 1];
  char *str2 = str;
  char t2[input_len+1];

  /* Check symbol rules. */
  for (i = 0; i < input_len; i++) {
    /* Digit or Letter or '@' or '.' or '-'. */
    if (!(isdigit(*str2) || isalpha(*str2) || *str2 == '@' ||
          *str2 == '.' || *str2 == '-')) {
      ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                      errmsg("invalid input syntax for emailaddr: \"%s\"", str)));
    }
    /* Exectly one '@'. */
    if ((*str2) == '@') {
      at_num++;
      at_pos = i;
      if (at_num > 1) {
      ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                      errmsg("invalid input syntax for emailaddr: \"%s\"", str)));
      }
    }
    /* Convert all letters to lower case. */
    t1[i] = tolower(*str2);
    str2++;
  }
  /* No @ in input string */
  if (at_num == 0) {
    ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                    errmsg("invalid input syntax for emailaddr: \"%s\"", str)));
  }

  t1[input_len] = '\0';

  memcpy(t2, t1, input_len + 1);

  /* Check local and domain format. */
  if (!dom_check(str, at_pos) || !loc_check(str, at_pos)) {
    ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                    errmsg("invalid input syntax for emailaddr: \"%s\"", str)));
  }

  result = (EmailAddr *)palloc(input_len + 1 + VARHDRSZ + 4);
  SET_VARSIZE(result, input_len + 1 + VARHDRSZ + 4);
  memcpy(result->addr, t1, input_len + 1);
  result->at_pos = at_pos;

  PG_RETURN_POINTER(result);
}

PG_FUNCTION_INFO_V1(emailaddr_out);

Datum emailaddr_out(PG_FUNCTION_ARGS) {
  EmailAddr *t = (EmailAddr *)PG_GETARG_VARLENA_P(0);
  int32 length = VARSIZE_ANY_EXHDR(t);
  int32 i = 0;
  char *result = "";
  char *ptr = t->addr;
  //char res[5];
  //pg_ltoa(t->at_pos, res);
  //result = psprintf("%s%s", result, res);
  for (i = 0; i < length-4; i++) {
    result = psprintf("%s%c", result, *ptr);
    ptr++;
  }

  PG_RETURN_CSTRING(result);
}

/*****************************************************************************
 * Help functions
 *****************************************************************************/

int dom_check(char *str, int32 at_pos) {
  int len = strlen(str) - at_pos-1;
  char *ptr = str;
  int yes = 0;
  ptr += at_pos + 1;
  if (len > MAX_DOMAIN_LEN || isdigit(*ptr) ||
      ptr[len - 1] == '.' || ptr[len - 1] == '-') {
    return 0;
  }
  ptr++;
  while (*ptr != '\0') {
    if (*ptr == '.' &&
        (*(ptr - 1) == '-' || *(ptr - 1) == '.' || *(ptr + 1) == '.' ||
         *(ptr + 1) == '-' || isdigit(*(ptr + 1)))) {
      return 0;
    }
    if (*ptr == '.')
      yes = 1;
    ptr++;
  }
  if (!yes)
    return 0;
  return 1;
}

int loc_check(char *str, int32 at_pos) {
  int len = at_pos;
  char *ptr = str;
  if (len > MAX_LOCAL_LEN || isdigit(*ptr) ||
      ptr[len - 1] == '.' || ptr[len - 1] == '-') {
    return 0;
  }
  ptr++;
  while (*ptr != '@') {
    if (*ptr == '.' &&
        (*(ptr - 1) == '-' || *(ptr - 1) == '.' || *(ptr + 1) == '.' ||
         *(ptr + 1) == '-' || isdigit(*(ptr + 1)) || *(ptr + 1) == '@')) {
      return 0;
    }
    ptr++;
  }
  return 1;
}

/* opetator = */
PG_FUNCTION_INFO_V1(emailaddr_eq);
Datum
emailaddr_eq(PG_FUNCTION_ARGS)
{
	EmailAddr    *a = (EmailAddr *) PG_GETARG_VARLENA_P(0);
	EmailAddr    *b = (EmailAddr *) PG_GETARG_VARLENA_P(1);

	PG_RETURN_BOOL(strcmp(a->addr, b->addr)==0);
}

/* opetator <> */
PG_FUNCTION_INFO_V1(emailaddr_ne);
Datum
emailaddr_ne(PG_FUNCTION_ARGS)
{
	EmailAddr    *a = (EmailAddr *) PG_GETARG_VARLENA_P(0);
	EmailAddr    *b = (EmailAddr *) PG_GETARG_VARLENA_P(1);

	PG_RETURN_BOOL(strcmp(a->addr, b->addr));
}

/* domain check ~ */
PG_FUNCTION_INFO_V1(emailaddr_ed);
Datum
emailaddr_ed(PG_FUNCTION_ARGS)
{
	EmailAddr    *a = (EmailAddr *) PG_GETARG_VARLENA_P(0);
  char * dom_a = a->addr;
	EmailAddr    *b = (EmailAddr *) PG_GETARG_VARLENA_P(1);
  char * dom_b = b->addr;
  dom_a += a->at_pos+1;
  dom_b += b->at_pos+1;
  
	PG_RETURN_BOOL(strcmp(dom_a, dom_b)==0);
}

/* domain check !~ */
PG_FUNCTION_INFO_V1(emailaddr_nd);
Datum
emailaddr_nd(PG_FUNCTION_ARGS)
{
	EmailAddr    *a = (EmailAddr *) PG_GETARG_VARLENA_P(0);
  char * dom_a = a->addr;
	EmailAddr    *b = (EmailAddr *) PG_GETARG_VARLENA_P(1);
  char * dom_b = b->addr;
  dom_a += a->at_pos+1;
  dom_b += b->at_pos+1;
  
	PG_RETURN_BOOL(strcmp(dom_a, dom_b));
}

/* operator > */
PG_FUNCTION_INFO_V1(emailaddr_gt);
Datum
emailaddr_gt(PG_FUNCTION_ARGS)
{
	EmailAddr    *a = (EmailAddr *) PG_GETARG_VARLENA_P(0);
  char * dom_a = a->addr;
  char loc_a[a->at_pos+1];

	EmailAddr    *b = (EmailAddr *) PG_GETARG_VARLENA_P(1);
  char * dom_b = b->addr;
  char loc_b[b->at_pos+1];

  char * tem_p = a->addr;
  int32 i = 0;
  int32 res = 0;

  /* a, b is equal */
  res = strcmp(a->addr, b->addr);
  if (res == 0)
  {
    PG_RETURN_BOOL(0);
  }

  dom_a += a->at_pos + 1;
  dom_b += b->at_pos + 1;
  res = strcmp(dom_a, dom_b);
  /* domain part is not equal */
  if (res > 0)
  {
    PG_RETURN_BOOL(1);
  }
  else if (res < 0)
  {
    PG_RETURN_BOOL(0);
  }

  /* domain part is equal, now compare local part */
  tem_p = a->addr;
  for(i=0; i<a->at_pos; i++)
  {
    loc_a[i] = (*tem_p);
    tem_p++;
  }
  loc_a[a->at_pos] = '\0';

  tem_p = b->addr;
  for(i=0; i<b->at_pos; i++)
  {
    loc_b[i] = (*tem_p);
    tem_p++;
  }
  loc_b[b->at_pos] = '\0';

  res = strcmp(loc_a, loc_b);
  if (res > 0)
  {
    PG_RETURN_BOOL(1);
  }
  else if (res < 0)
  {
    PG_RETURN_BOOL(0);
  }

  /* this should never execute */
	PG_RETURN_BOOL(0);
}

/* operator <= */
PG_FUNCTION_INFO_V1(emailaddr_le);

Datum
emailaddr_le(PG_FUNCTION_ARGS)
{
	EmailAddr    *a = (EmailAddr *) PG_GETARG_VARLENA_P(0);
  char * dom_a = a->addr;
  char loc_a[a->at_pos+1];

	EmailAddr    *b = (EmailAddr *) PG_GETARG_VARLENA_P(1);
  char * dom_b = b->addr;
  char loc_b[b->at_pos+1];

  char * tem_p = a->addr;
  int32 i = 0;
  int32 res = 0;

  /* a, b is equal */
  res = strcmp(a->addr, b->addr);
  if (res == 0)
  {
    PG_RETURN_BOOL(1);
  }

  dom_a += a->at_pos + 1;
  dom_b += b->at_pos + 1;
  res = strcmp(dom_a, dom_b);
  /* domain part is not equal */
  if (res > 0)
  {
    PG_RETURN_BOOL(0);
  }
  else if (res < 0)
  {
    PG_RETURN_BOOL(1);
  }

  /* domain part is equal, now compare local part */
  tem_p = a->addr;
  for(i=0; i<a->at_pos; i++)
  {
    loc_a[i] = (*tem_p);
    tem_p++;
  }
  loc_a[a->at_pos] = '\0';

  tem_p = b->addr;
  for(i=0; i<b->at_pos; i++)
  {
    loc_b[i] = (*tem_p);
    tem_p++;
  }
  loc_b[b->at_pos] = '\0';

  res = strcmp(loc_a, loc_b);
  if (res > 0)
  {
    PG_RETURN_BOOL(0);
  }
  else if (res < 0)
  {
    PG_RETURN_BOOL(1);
  }

  /* this should never execute */
	PG_RETURN_BOOL(1);
}

/* operator < */
PG_FUNCTION_INFO_V1(emailaddr_lt);
Datum
emailaddr_lt(PG_FUNCTION_ARGS)
{
  EmailAddr    *b = (EmailAddr *) PG_GETARG_VARLENA_P(0);
  char * dom_b = b->addr;
  char loc_b[b->at_pos+1];

	EmailAddr    *a = (EmailAddr *) PG_GETARG_VARLENA_P(1);
  char * dom_a = a->addr;
  char loc_a[a->at_pos+1];



  char * tem_p = a->addr;
  int32 i = 0;
  int32 res = 0;

  /* a, b is equal */
  res = strcmp(a->addr, b->addr);
  if (res == 0)
  {
    PG_RETURN_BOOL(0);
  }

  dom_a += a->at_pos + 1;
  dom_b += b->at_pos + 1;
  res = strcmp(dom_a, dom_b);
  /* domain part is not equal */
  if (res > 0)
  {
    PG_RETURN_BOOL(1);
  }
  else if (res < 0)
  {
    PG_RETURN_BOOL(0);
  }

  /* domain part is equal, now compare local part */
  tem_p = a->addr;
  for(i=0; i<a->at_pos; i++)
  {
    loc_a[i] = (*tem_p);
    tem_p++;
  }
  loc_a[a->at_pos] = '\0';

  tem_p = b->addr;
  for(i=0; i<b->at_pos; i++)
  {
    loc_b[i] = (*tem_p);
    tem_p++;
  }
  loc_b[b->at_pos] = '\0';

  res = strcmp(loc_a, loc_b);
  if (res > 0)
  {
    PG_RETURN_BOOL(1);
  }
  else if (res < 0)
  {
    PG_RETURN_BOOL(0);
  }

  /* this should never execute */
	PG_RETURN_BOOL(0);
}

/* operator >= */
PG_FUNCTION_INFO_V1(emailaddr_ge);
Datum
emailaddr_ge(PG_FUNCTION_ARGS)
{
  EmailAddr    *b = (EmailAddr *) PG_GETARG_VARLENA_P(0);
  char * dom_b = b->addr;
  char loc_b[b->at_pos+1];

	EmailAddr    *a = (EmailAddr *) PG_GETARG_VARLENA_P(1);
  char * dom_a = a->addr;
  char loc_a[a->at_pos+1];



  char * tem_p = a->addr;
  int32 i = 0;
  int32 res = 0;

  /* a, b is equal */
  res = strcmp(a->addr, b->addr);
  if (res == 0)
  {
    PG_RETURN_BOOL(1);
  }

  dom_a += a->at_pos + 1;
  dom_b += b->at_pos + 1;
  res = strcmp(dom_a, dom_b);
  /* domain part is not equal */
  if (res > 0)
  {
    PG_RETURN_BOOL(0);
  }
  else if (res < 0)
  {
    PG_RETURN_BOOL(1);
  }

  /* domain part is equal, now compare local part */
  tem_p = a->addr;
  for(i=0; i<a->at_pos; i++)
  {
    loc_a[i] = (*tem_p);
    tem_p++;
  }
  loc_a[a->at_pos] = '\0';

  tem_p = b->addr;
  for(i=0; i<b->at_pos; i++)
  {
    loc_b[i] = (*tem_p);
    tem_p++;
  }
  loc_b[b->at_pos] = '\0';

  res = strcmp(loc_a, loc_b);
  if (res > 0)
  {
    PG_RETURN_BOOL(0);
  }
  else if (res < 0)
  {
    PG_RETURN_BOOL(1);
  }

  /* this should never execute */
	PG_RETURN_BOOL(1);
}

/* btree compare function */
PG_FUNCTION_INFO_V1(emailaddr_cmp);

Datum
emailaddr_cmp(PG_FUNCTION_ARGS)
{
	EmailAddr    *a = (EmailAddr *)PG_GETARG_VARLENA_P(0);
	EmailAddr    *b = (EmailAddr *)PG_GETARG_VARLENA_P(1);

	PG_RETURN_INT32(strcmp(a->addr, b->addr));
}

/* hash function */
PG_FUNCTION_INFO_V1(emailaddr_hash);

Datum
emailaddr_hash(PG_FUNCTION_ARGS)
{
	EmailAddr	  *email = (EmailAddr *)PG_GETARG_VARLENA_P(0);
  int32 length = VARSIZE_ANY_EXHDR(email);
	char	      *str = email->addr;
	Datum		    result;
  
	//str = str_tolower(VARDATA_ANY(txt), VARSIZE_ANY_EXHDR(txt), DEFAULT_COLLATION_OID);
	result = hash_any((unsigned char *) str, length);
	//pfree(str);

	/* Avoid leaking memory for toasted inputs */
	//PG_FREE_IF_COPY(email, 0);

	PG_RETURN_DATUM(result);
}
