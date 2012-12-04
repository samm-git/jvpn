/*
 * wrapper for ncui to hide ps args (c) Alex Samorukov
 *
 * save_ps_display_args() comes from ps_status.c, PostgreSQL
 * Copyright (c) 2000-2010, PostgreSQL Global Development Group */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

/* save the original argv[] location here */
static int  save_argc;
static char **save_argv;
extern char **environ;
static char *ps_buffer;             /* will point to argv area */
static size_t ps_buffer_size; /* space determined at run time */

char    **
save_ps_display_args(int argc, char **argv)
{
      save_argc = argc;
      save_argv = argv;

      /*
       * If we're going to overwrite the argv area, count the available space.
       * Also move the environment to make additional room.
       */
      {
            char     *end_of_area = NULL;
            char    **new_environ;
            int               i;

            /*
             * check for contiguous argv strings
             */
            for (i = 0; i < argc; i++)
            {
                  if (i == 0 || end_of_area + 1 == argv[i])
                        end_of_area = argv[i] + strlen(argv[i]);
            }

            if (end_of_area == NULL)      /* probably can't happen? */
            {
                  ps_buffer = NULL;
                  ps_buffer_size = 0;
                  return argv;
            }

            /*
             * check for contiguous environ strings following argv
             */
            for (i = 0; environ[i] != NULL; i++)
            {
                  if (end_of_area + 1 == environ[i])
                        end_of_area = environ[i] + strlen(environ[i]);
            }

            ps_buffer = argv[0];
            ps_buffer_size = end_of_area - argv[0];

            /*
             * move the environment out of the way
             */
            new_environ = (char **) malloc((i + 1) * sizeof(char *));
            for (i = 0; environ[i] != NULL; i++)
                  new_environ[i] = strdup(environ[i]);
            new_environ[i] = NULL;
            environ = new_environ;
      }

      /*
       * If we're going to change the original argv[] then make a copy for
       * argument parsing purposes.
       */
      {
            char    **new_argv;
            int               i;

            new_argv = (char **) malloc((argc + 1) * sizeof(char *));
            for (i = 0; i < argc; i++) {
                  new_argv[i] = strdup(argv[i]);
            }
            new_argv[argc] = NULL;
            argv = new_argv;
      }
      return argv;
}


int
main(int argc, char **argv)
{
    void *handle;
    char *error;

   handle = dlopen("./libncui.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }

   save_argc = argc;
   save_argv = argv;

   dlerror();    /* Clear any existing error */

   int (* ncui)(int, char **) = dlsym(handle,"main");
   argv = save_ps_display_args(argc, argv);
   int i;
   for (i = 1; i < save_argc; i++) {
     memset(save_argv[i], 0 ,strlen(save_argv[i]));
   }
   save_argc = 1;

   ncui(argc, argv);

   if ((error = dlerror()) != NULL)  {
        fprintf(stderr, "%s\n", error);
        exit(EXIT_FAILURE);
    }

    dlclose(handle);
    exit(EXIT_SUCCESS);
}