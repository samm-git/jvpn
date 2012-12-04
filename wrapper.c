/* 
 * ncui wrapper, which reads parameters from command line and launching ncui.
 * This is done to avoid DSID visibility in process list

 * The author has placed this work in the Public Domain, thereby relinquishing
 * all copyrights. Everyone is free to use, modify, republish, sell or give away
 * this work without prior consent from anybody.

 * This software is provided on an "as is" basis, without warranty of any
 * kind. Use at your own risk! Under no circumstances shall the author(s) or
 * contributor(s) be liable for damages resulting directly or indirectly from
 * the use or non-use of this software.
*/


#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>

#define BUF_SIZE 1024
#define MAX_ARGS 20

int
main(int argc, char **argv)
{
   void *handle;
   char *error;
   char **newargv;
   char buffer[BUF_SIZE];
   int newargc = 0, len;

   handle = dlopen("./libncui.so", RTLD_LAZY);
   if (!handle) {
         fprintf(stderr, "%s\n", dlerror());
         exit(EXIT_FAILURE);
   }

   dlerror();    /* Clear any existing error */
   newargv = (char **) malloc ((MAX_ARGS + 1) * sizeof (char *));

   while(fgets(buffer, BUF_SIZE, stdin)){
     len = strlen(buffer);
     newargv[newargc] = malloc (sizeof (char *) * (len + 1));
     // remove eol
     if(buffer[len-1]=='\n') buffer[len-1]='\0';
     snprintf(newargv[newargc], len + 1, "%s", buffer);
     newargc++;
     if(newargc == MAX_ARGS) break;
   }
   if(!newargc) {
        fprintf(stderr, "Error: no arguments provided\n");
        exit(EXIT_FAILURE);
   }

   int (* ncui)(int, char **) = dlsym(handle,"main");
   ncui(newargc, newargv);

   if ((error = dlerror()) != NULL)  {
        fprintf(stderr, "%s\n", error);
        exit(EXIT_FAILURE);
   }

    dlclose(handle);
    exit(EXIT_SUCCESS);
}
