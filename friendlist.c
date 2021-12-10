/*
 * friendlist.c - [Starting code for] a web-based friend-graph manager.
 *
 * Based on:
 *  tiny.c - A simple, iterative HTTP/1.0 Web server that uses the 
 *      GET method to serve static and dynamic content.
 *   Tiny Web server
 *   Dave O'Hallaron
 *   Carnegie Mellon University
 */
#include "csapp.h"
#include "dictionary.h"
#include "more_string.h"

static void* doit(void* connfd_p);
static dictionary_t *read_requesthdrs(rio_t *rp);
static void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *d);
static void clienterror(int fd, char *cause, char *errnum,
                        char *shortmsg, char *longmsg);
static void print_stringdictionary(dictionary_t *d);
static void serve_request(int fd, dictionary_t *query);
static dictionary_t *list_of_friends;
static void befriend(int fd, dictionary_t *query, dictionary_t *list_of_friends);
static void friends(int fd, dictionary_t *query);
static void unfriend(int fd, dictionary_t *query);
static void introduce(int fd, dictionary_t *query);
static sem_t mutex; 

int main(int argc, char **argv)
{
  int listenfd, connfd;
  char hostname[MAXLINE], port[MAXLINE];
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;
  pthread_t th;
  int *connfd_p;
  Sem_init(&mutex, 0, 1);

  /* Check command line args */
  if (argc != 2)
  {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }

  listenfd = Open_listenfd(argv[1]);

  /* Don't kill the server if there's an error, because
     we want to survive errors due to a client. But we
     do want to report errors. */
  exit_on_error(0);

  /* Also, don't stop on broken connections: */
  Signal(SIGPIPE, SIG_IGN);
  list_of_friends = make_dictionary(COMPARE_CASE_SENS, NULL);
  while (1)
  {
    clientlen = sizeof(clientaddr);
    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    connfd_p = malloc(sizeof(int)); 
    (*connfd_p) = connfd;
    if (connfd >= 0)
    {
      Getnameinfo((SA *)&clientaddr, clientlen, hostname, MAXLINE,
                  port, MAXLINE, 0);
      printf("Accepted connection from (%s, %s)\n", hostname, port);
      Pthread_create(&th, NULL, doit, connfd_p);
      Pthread_detach(th);
    }
  }
}

/*
 * doit - handle one HTTP request/response transaction
 */
void* doit(void* connfd_p)
{
  char buf[MAXLINE], *method, *uri, *version;
  rio_t rio;
  dictionary_t *headers, *query;
  int fd = *(int *)connfd_p;
  free(connfd_p);

  printf("THIS IS YOUR IQ: %d\n", fd); 

  

  /* Read request line and headers */
  Rio_readinitb(&rio, fd);
  if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
  {
    Close(fd);
    return NULL;
  }

  printf("%s", buf);

  if (!parse_request_line(buf, &method, &uri, &version))
  {
    clienterror(fd, method, "400", "Bad Request",
                "Friendlist did not recognize the request");
  }
  else
  {
    if (strcasecmp(version, "HTTP/1.0") && strcasecmp(version, "HTTP/1.1"))
    {
      printf("HTTP/1.0 \n");
      fflush(stdout);
      clienterror(fd, version, "501", "Not Implemented",
                  "Friendlist does not implement that version");
    }
    else if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
    {
      printf("GET POST \n");
      fflush(stdout);
      clienterror(fd, method, "501", "Not Implemented",
                  "Friendlist does not implement that method");
    }
    else
    {
      printf("header\n");
      fflush(stdout);
      headers = read_requesthdrs(&rio);

      /* Parse all query arguments into a dictionary */
      query = make_dictionary(COMPARE_CASE_SENS, free);
      parse_uriquery(uri, query);
      if (!strcasecmp(method, "POST"))
        read_postquery(&rio, headers, query);

      /* For debugging, print the dictionary */
      print_stringdictionary(query);

      /* You'll want to handle different queries here,
         but the intial implementation always returns
         nothing: */
      if (starts_with("/befriend", uri))
      {

        befriend(fd, query, list_of_friends);
      }
      else if (starts_with("/friends", uri))
      {
        printf("from friends \n");
        friends(fd, query);
      }
      else if (starts_with("/unfriend", uri))
      {
        unfriend(fd, query);
      }
      else if (starts_with("/introduce", uri))
      {

        introduce(fd, query);
      }
      else
      {
        serve_request(fd, query);
      }

      /* Clean up */
      free_dictionary(query);
      free_dictionary(headers);
    }

    /* Clean up status line */
    free(method);
    free(uri);
    free(version);
  }
  Close(fd);
  return NULL; 
}

/*
 * read_requesthdrs - read HTTP request headers
 */
dictionary_t *read_requesthdrs(rio_t *rp)
{
  char buf[MAXLINE];
  dictionary_t *d = make_dictionary(COMPARE_CASE_INSENS, free);

  Rio_readlineb(rp, buf, MAXLINE);
  printf("%s", buf);
  while (strcmp(buf, "\r\n"))
  {
    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
    parse_header_line(buf, d);
  }

  return d;
}

void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *dest)
{
  char *len_str, *type, *buffer;
  int len;

  len_str = dictionary_get(headers, "Content-Length");
  len = (len_str ? atoi(len_str) : 0);

  type = dictionary_get(headers, "Content-Type");

  buffer = malloc(len + 1);
  Rio_readnb(rp, buffer, len);
  buffer[len] = 0;

  if (!strcasecmp(type, "application/x-www-form-urlencoded"))
  {
    parse_query(buffer, dest);
  }

  free(buffer);
}

static char *ok_header(size_t len, const char *content_type)
{
  char *len_str, *header;

  header = append_strings("HTTP/1.0 200 OK\r\n",
                          "Server: Friendlist Web Server\r\n",
                          "Connection: close\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n",
                          "Content-type: ", content_type, "\r\n\r\n",
                          NULL);
  free(len_str);

  return header;
}

/*
 * serve_request - example request handler
 */
static void serve_request(int fd, dictionary_t *query)
{
  size_t len;
  char *body, *header;

  body = strdup("alice\nbob");

  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

static void unfriend(int fd, dictionary_t *query)
{
  size_t len;
  char *body, *header;
  char *user;
  char *friends;

  friends = dictionary_get(query, "friends");
  user = dictionary_get(query, "user");
  char **friends_to_remove = split_string(friends, '\n');
  P(&mutex);
  dictionary_t *user_friends = dictionary_get(list_of_friends, user);
  if (user_friends == NULL)
  {
    body = strdup("");
  }
  else
  {

    int i;
    for (i = 0; friends_to_remove[i] != NULL; i++)
    {
      const char *val = friends_to_remove[i];
      dictionary_remove(user_friends, val);
      print_stringdictionary(user_friends);
    }

    const char **list = dictionary_keys(user_friends);
    body = strdup(join_strings(list, '\n'));
  }

  dictionary_set(list_of_friends, user, user_friends);

  int j;
  for (j = 0; friends_to_remove[j] != NULL; j++)
  {
    dictionary_t *friends_of_user = dictionary_get(list_of_friends, friends_to_remove[j]);
    if (friends_of_user == NULL)
    {
      continue;
    }
    dictionary_remove(friends_of_user, user);
    dictionary_set(list_of_friends, friends_to_remove[j], friends_of_user);
  }
  V(&mutex);

  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

static void introduce(int fd, dictionary_t *query)
{
  size_t len;
  char *body, *header;
  char *user;
  char *host;
  char *port;
  char *friends;
  //char *buffer;
  char buf[MAXLINE];
  size_t len_request;
  int clientfd;
  char *friends_from_server = "";
  rio_t rio;
  ssize_t n;

  host = dictionary_get(query, "host");
  port = dictionary_get(query, "port");

  user = dictionary_get(query, "user");
  friends = dictionary_get(query, "friend");

  char *get_request = "GET /friends?user=";
  char *req = append_strings(get_request, friends, " HTTP/1.1\r\n\r\n", NULL);
  len_request = strlen(req);

  clientfd = Open_clientfd(host, port);

  Rio_writen(clientfd, req, len_request);
  Rio_readinitb(&rio, clientfd);

  // check if it's 200
  Rio_readlineb(&rio, buf, MAXLINE);

  char *version;
  char *status;
  char *descrpt;
  int parse_line_stat = parse_status_line(buf, &version, &status, &descrpt);
  int statuscheck = strcmp(status, "200");
  dictionary_t *incoming_nukes = make_dictionary(COMPARE_CASE_SENS, NULL);  
  
  if (!strcmp(status, "200"))
  {
    
    while ((Rio_readlineb(&rio, buf, MAXLINE)) != 2)
    {
    }
    
     while ((Rio_readlineb(&rio, buf, MAXLINE)) != 0)
    {
      int size = strlen(buf);
      buf[size-1] = '\0';

      
      
      if(strcmp(buf, user))
      {
        dictionary_set(incoming_nukes, buf, NULL); // user <--friends
      }

      // friends <-- user
      ///dictionary_t *friend_of_my_friend = dictionary_get(list_of_friends, buf);
      //if (friend_of_my_friend == NULL)
      //{
        //friend_of_my_friend = make_dictionary(COMPARE_CASE_SENS, NULL);
      //}
      //dictionary_set(friend_of_my_friend, user, NULL);
      //dictionary_set(friend_of_my_friend, friends, NULL); 
      //dictionary_set(list_of_friends, buf, friend_of_my_friend);
      //dictionary_set(another_dict, buf, NULL); 

    }
    /*
    dictionary_t *friends_user = dictionary_get(list_of_friends, user);
    if (friends_user == NULL)
    {
      friends_user = make_dictionary(COMPARE_CASE_SENS, NULL);
    }

    dictionary_t *another_dict = dictionary_get(list_of_friends, friends);
    if(another_dict == NULL){
      another_dict = make_dictionary(COMPARE_CASE_SENS, NULL);
    }
    if(!strcmp(user, friends))
    {
      //send an error 
      return;
    }
    dictionary_set(another_dict, user, NULL); 

    while ((Rio_readlineb(&rio, buf, MAXLINE)) != 0)
    {
      int size = strlen(buf);
      buf[size-1] = '\0';

      

      if(strcmp(buf, user))
      {
        printf("Adding friend: %s\n", buf); 
        dictionary_set(friends_user, buf, NULL); // user <--friends
      }

      // friends <-- user
      dictionary_t *friend_of_my_friend = dictionary_get(list_of_friends, buf);
      if (friend_of_my_friend == NULL)
      {
        friend_of_my_friend = make_dictionary(COMPARE_CASE_SENS, NULL);
      }
      dictionary_set(friend_of_my_friend, user, NULL);
      dictionary_set(friend_of_my_friend, friends, NULL); 
      dictionary_set(list_of_friends, buf, friend_of_my_friend);
      dictionary_set(another_dict, buf, NULL); 

    }
    
    dictionary_set(friends_user, friends, NULL);
    dictionary_set(list_of_friends, user, friends_user);
    dictionary_set(list_of_friends, friends, another_dict); 
    //V(&mutex); 

    const char **new_friends = dictionary_keys(friends_user);
    body = strdup(join_strings(new_friends, '\n'));
    */
  }
  //else {
    //
  //}

  char **list = dictionary_keys(incoming_nukes); 

  int i = 0;
  while(list[i] != NULL)
  { 
    i++;
  }
  P(&mutex);
  dictionary_t *friends_user = dictionary_get(list_of_friends, user);
  if (friends_user == NULL)
  {
    friends_user = make_dictionary(COMPARE_CASE_SENS, NULL);
  }
  dictionary_set(friends_user, friends, NULL);
  int index;
  for (index = 0; list[index] != NULL; index++)
  {

    dictionary_set(friends_user, list[index], NULL);
    print_stringdictionary(friends_user);
  }

  const char **new_friends = dictionary_keys(friends_user);
  int ii = 0;
  while(new_friends[ii] != NULL) 
  { 
    ii++;

  }
  body = strdup(join_strings(new_friends, '\n'));
  dictionary_set(list_of_friends, user, friends_user);
  print_stringdictionary(list_of_friends);

  int j;
  for (j = 0; list[j] != NULL; j++)
  {
    dictionary_t *friend_of_my_friend = dictionary_get(list_of_friends, list[j]);
    if (friend_of_my_friend == NULL)
    {
      friend_of_my_friend = make_dictionary(COMPARE_CASE_SENS, NULL);
    }
    dictionary_set(friend_of_my_friend, user, NULL);
    dictionary_set(list_of_friends, list[j], friend_of_my_friend);
  }
  V(&mutex);

  len = strlen(body);
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));

  printf("Response headers:\n");
  printf("%s", header);

  free(header);


  Rio_writen(fd, body, len);

  free(body);
}


static void friends(int fd, dictionary_t *query)
{

  size_t len;
  char *body, *header;
  char *user;
  user = dictionary_get(query, "user");
  P(&mutex);
  dictionary_t *friends_from_user = dictionary_get(list_of_friends, user);
  V(&mutex);
  if (friends_from_user == NULL)
  {
    dictionary_set(list_of_friends, user, NULL);
    body = strdup("");
  }
  else
  {
    const char **list = dictionary_keys(friends_from_user);
    body = strdup(join_strings(list, '\n'));
  }

  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}
static void befriend(int fd, dictionary_t *query, dictionary_t *list_of_friends)
{

  size_t len;
  char *body, *header;
  char *user;
  char *friends;
  // values have to be a dictonary
  // store a list of friends for each
  // make a value a dictionary again
  // make the keys in that dictionary
  //

  friends = dictionary_get(query, "friends");
  user = dictionary_get(query, "user");

  char **list;
  list = split_string(friends, '\n');

  P(&mutex);
  dictionary_t *friends_user = dictionary_get(list_of_friends, user);
  if (friends_user == NULL)
  {
    friends_user = make_dictionary(COMPARE_CASE_SENS, NULL);
  }

  // adding friends to user
  int index;
  for (index = 0; list[index] != NULL; index++)
  {

    dictionary_set(friends_user, list[index], NULL);
    print_stringdictionary(friends_user);
  }

  const char **new_friends = dictionary_keys(friends_user);
  body = strdup(join_strings(new_friends, '\n'));
  dictionary_set(list_of_friends, user, friends_user);
  print_stringdictionary(list_of_friends);

  int i;
  for (i = 0; list[i] != NULL; i++)
  {
    dictionary_t *friend_of_my_friend = dictionary_get(list_of_friends, list[i]);
    if (friend_of_my_friend == NULL)
    {
      friend_of_my_friend = make_dictionary(COMPARE_CASE_SENS, NULL);
    }
    dictionary_set(friend_of_my_friend, user, NULL);
    dictionary_set(list_of_friends, list[i], friend_of_my_friend);
  }
  V(&mutex);

  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}
/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, char *cause, char *errnum,
                 char *shortmsg, char *longmsg)
{
  size_t len;
  char *header, *body, *len_str;

  body = append_strings("<html><title>Friendlist Error</title>",
                        "<body bgcolor="
                        "ffffff"
                        ">\r\n",
                        errnum, " ", shortmsg,
                        "<p>", longmsg, ": ", cause,
                        "<hr><em>Friendlist Server</em>\r\n",
                        NULL);
  len = strlen(body);

  /* Print the HTTP response */
  header = append_strings("HTTP/1.0 ", errnum, " ", shortmsg, "\r\n",
                          "Content-type: text/html; charset=utf-8\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n\r\n",
                          NULL);
  free(len_str);

  Rio_writen(fd, header, strlen(header));
  Rio_writen(fd, body, len);

  free(header);
  free(body);
}

static void print_stringdictionary(dictionary_t *d)
{
  int i, count;

  count = dictionary_count(d);
  for (i = 0; i < count; i++)
  {
    printf("%s=%s\n",
           dictionary_key(d, i),
           (const char *)dictionary_value(d, i));
  }
  printf("\n");
}
