#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <wordexp.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

const int max = 1073741823; 
char logpath[1024], name[1024], room[11], t[11], status, role;
unsigned char ciphertext[1024], pass[1024];
FILE *file;
long room_num, t_num;

int parse_cmdline(int argc, char *argv[]) {
  //printf("here\n"); 
  //char time_str[INT_MAX], a_or_l;
  int opt = -1;
  int is_good = -1;
  int conflict_status = 0; 
  int is_guest = 0; 
  int is_employee = 0;
  int i;
  char *eptr;
  //pick up the switches
  while ((opt = getopt(argc, argv, "T:K:E:G:ALR:B:")) != -1) {
    //printf("%s\n", argv[optind - 1]);
    //printf("%d\n", optind);
    switch(opt) {
      case 'B':
        printf("unimplemented\n");
        exit(255);
        break;

      case 'T':
        strcpy(t, argv[optind - 1]);

        //printf("%d\n", strlen(t));
        for(i = 0; i < strlen(t); i++) {
          //printf("%c\n", t[i]);
          if(isalpha(t[i])) {
            printf("invalid\n");
            exit(255);
          }
        }

        //printf("t: %s\n", t);

        t_num = strtol(t, &eptr, 10);
        //printf("t_num: %ld\n", t_num);
        if(t_num < 0 || t_num > max) {
          printf("invalid\n");
          exit(255);
        }   
 

        //printf("c to i: %d\n", t);
        //printf("here\n");       
        break;

      case 'K':
        //printf("%s", argv[optind - 1]);
        strcpy(pass, argv[optind - 1]);
 
        for(i = 0; i < strlen(pass); i++) {
          if(!isalpha(pass[i]) && !isdigit(pass[i])) {
            printf("invalid\n");
            exit(255);
          }
        }

        printf("pass: %s\n", pass);
        break; 

      case 'A':
        status = 'A';
        room_num = -1;
        if(conflict_status == 1) {
          printf("invalid\n");
          exit(255);
        }
        conflict_status = 1;
        //printf("status: %c\n", status);
        break;

      case 'L':
        status = 'L';
        room_num = -1;
        if(conflict_status == 1) {
          printf("invalid\n");
          exit(255);
        }
        conflict_status = 1;
        //printf("status: %c\n", status);
        break;

      case 'E':
        memset(name, '\0', sizeof name);
        role = 'E';
        strcpy(name, argv[optind - 1]);

        for(i = 0; i < strlen(name); i++) {
          if(!isalpha(name[i])) {
            printf("invalid\n");
            exit(255);
          }
        }

        if(is_guest == 1) {
          printf("invalid\n");
          exit(255);
        }

        is_employee = 1;

        //printf("name: %s\n", name);
        break;

      case 'G':
        memset(name, '\0', sizeof name);
        role = 'G';
      strcpy(name, argv[optind - 1]);

      for(i = 0; i < strlen(name); i++) {
          if(!isalpha(name[i])) {
            printf("invalid\n");
            exit(255);
          }
        }

      if(is_employee == 1) {
          printf("invalid\n");
          exit(255);
        }

        is_guest = 1;

        //printf("name: %s\n", name);
        break;

      case 'R':
        strcpy(room, argv[optind - 1]);

        for(i = 0; i < strlen(room); i++) {
          if(isalpha(room[i])) {
            printf("invalid\n");
            exit(255);
          }
        }

        //printf("room: %s\n", room);

        room_num = strtol(room, &eptr, 10);
        //printf("room_num: %ld\n", room_num);
        if(room_num < 0 || room_num > max) {
          printf("invalid\n");
          exit(255);
        }

        //room = room - '0';
        //printf("room: %d\n", room);
        break;


      default:
        printf("uknown option\n");
        exit(255);
        break;
    }

  //strcat(str, "\n");
  }

  //pick up the positional argument for log path
  if(optind < argc) {
    //logpath = argv[optind];
    strcpy(logpath, argv[optind]);
  }

  //printf("logpath: %s\n", logpath);
  return is_good;
  //return 0;
}

int encrypt_key(unsigned char *input, int inlen, unsigned char *key, 
  unsigned char *iv, unsigned char *ciphertext) {
    
  FILE *bin;
  int i = 0, keyfound = 1, outlen, ciphlen;
  EVP_CIPHER_CTX *ctx;

  char keyfile[1024];

  strcpy(keyfile, logpath);
  strcat(keyfile, ".key"); 

  //bin = fopen(keyfile, "w+");

  ctx = EVP_CIPHER_CTX_new();

  //add a bunch of 'x' characters at the end of the message to be encrypted
  for(i = strlen(input); i < inlen + 10; i++) {
    input[i] = 'x';
  }

  input[i] = '\0';

  //handle encryption of the input
  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, ciphertext, &outlen, input, inlen + 10);
  ciphlen = outlen;
  EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen);
  ciphlen += outlen;
  //fwrite(ciphertext, 1, ciphlen, bin);
  EVP_CIPHER_CTX_free(ctx);

  //fwrite(ciphertext, 1, ciphlen, bin);
  //fclose(bin);

  return ciphlen;
}

int encrypt_log(unsigned char *input, int inlen, unsigned char *key, 
  unsigned char *iv, unsigned char *ciphertext) {
    
  //FILE *bin;
  int i, outlen, ciphlen;
  EVP_CIPHER_CTX *ctx;

  //char keyfile[1024];

  //bin = fopen(keyfile, "w+");

  ctx = EVP_CIPHER_CTX_new();

  //add a bunch of 'x' characters at the end of the message to be encrypted
  for(i = strlen(input); i < inlen + 10; i++) {
    input[i] = 'x';
  }

  input[i] = '\0';
  //printf("%s\n", input);
 
  //handle encryption of the input
  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, ciphertext, &outlen, input, inlen + 10);
  ciphlen = outlen;
  EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen);
  ciphlen += outlen;
  //fwrite(ciphertext, 1, ciphlen, bin);
  //printf("ciphlen: %d\n", ciphlen);
  EVP_CIPHER_CTX_free(ctx);
  //fwrite(ciphertext, 1, ciphlen, bin);
  //fclose(bin);

  return ciphlen;
}

int decrypt_log(unsigned char *input, int inlen, unsigned char *key, 
  unsigned char *iv, unsigned char *msgtxt) {

  int i, outlen, msglen;
  EVP_CIPHER_CTX *ctx;

  //handle decryption of the input
  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
  EVP_DecryptUpdate(ctx, msgtxt, &outlen, input, inlen);
  msglen = outlen;
  EVP_DecryptFinal_ex(ctx, msgtxt + outlen, &outlen);
  msglen += outlen;
  EVP_CIPHER_CTX_free(ctx);

  msgtxt[msglen] = '\0';

  //printf("msgtxt: %s\n", msgtxt);

  /*confirm the decrypted message by checking the 'x' characters that was added during
  /encryption*/
  for(i = strlen(msgtxt) - 1; i > strlen(msgtxt) - 11; i--) {
    if(msgtxt[i] != 'x') {
      return 0; //return 0 if its not the correct message
    }
  }

  //take away the added 'x' characters
  for(i = strlen(msgtxt) - 10; i < strlen(msgtxt); i++) {
    //msgtxt[strlen(msgtxt) - 10] = '\0';
    msgtxt[i] = '\0';
  }
   
  return msglen;
}

int main(int argc, char *argv[]) {
  int result, recorded_time;
  char entry[1024], buffer[1024];
  unsigned char iv[1024] = "02346378adehgfhl", file_txt[4096];
  char tmp_name[1024], last_occurence_name[1024];
  char tmp_status, tmp_role, last_occurence_status;
  int tmp_time, tmp_room, last_occurence_room, same_person;
  int leaving_room;

  result = parse_cmdline(argc, argv);
  
  sprintf(entry, "%s %ld %c %c %ld", name, t_num, status, role, room_num);

  if(access(logpath, F_OK) == -1) { //file doesn't exist yet

    if(room_num > -1 || status == 'L') { /*can't enter a room or leave the galery at the very start*/
      printf("invalid: can't enter a room or leave on an empty gallery\n");
      exit(255);
    }

    file = fopen(logpath, "w+");
    
    fprintf(file, "%ld                 \n%s\n", t_num, entry);
    
    fseek(file, 0L, SEEK_END);
    int file_size = ftell(file);
    fseek(file, 0L, SEEK_SET);

  unsigned char *file_data = malloc(file_size + 10);

  fread(file_data, sizeof *file_data, file_size, file);   
  //printf("buffer_len: %d\n", strlen(entry));
  
    /*encrypt key here*/
    /*encrypt file here*/
    int enc = encrypt_log(file_data, strlen(file_data), pass, iv, ciphertext);
    fseek(file, 0L, SEEK_SET);
    fwrite(ciphertext, 1, enc, file);
  } else {
    //char indata[4096];
    file = fopen(logpath, "r+");

    fseek(file, 0L, SEEK_END);
  int file_size = ftell(file);
  fseek(file, 0L, SEEK_SET);
  
  //fscanf(file, "%d\n", &recorded_time); 

  unsigned char *file_data = malloc(file_size);

  fread(file_data, sizeof *file_data, file_size, file);
  printf("%s\n", file_data);
    /*decrypt key here*/

    /*compare decrypted key to the password*/

    /*decrypt file here*/
  int dec = decrypt_log(file_data, file_size, pass, iv, file_txt);

  if(dec == 0) {
    printf("invalid (decryption)\n");
    fclose(file);
    exit(255);
  }

  sscanf(file_txt, "%d\n", &recorded_time);

    if(t_num <= recorded_time) {
      printf("invalid (time)\n");
      fclose(file);
      exit(255);
    }

    fclose(file);

    /*rewrite the log file*/
    file = fopen(logpath, "w+");
    fprintf(file, "%s", file_txt);
    rewind(file);
    
    int skip;
    fscanf(file, "%d\n", &skip);

    /*handle new entry*/
    while(fgets(buffer, sizeof buffer, file)) {
      sscanf(buffer,"%s %d %c %c %d", tmp_name, &tmp_time, &tmp_status, &tmp_role, &tmp_room);
      //printf("buffer: %sentry: %s\n", buffer, entry);
      if(strcmp(name, tmp_name) == 0 && role == tmp_role) {
        same_person = 1;
        strcpy(last_occurence_name, tmp_name);
        last_occurence_room = tmp_room;
        last_occurence_status = tmp_status;
        //last_occurence_role = tmp_role;
      } else {
        memset(tmp_name, '\0', sizeof tmp_name);
      }
    }

    if(same_person == 0) { //person is not in the log yet
      if(status == 'L') {
        printf("invalid: can't leave without entering gallery\n");
        rewind(file);
        fwrite(file_data, 1, file_size, file);
        fclose(file);
        exit(255);
      } else if(room_num > -1) {
        printf("invalid: can't enter room without entering gallery\n");
        rewind(file);
        fwrite(file_data, 1, file_size, file);
        fclose(file);
        exit(255);
      }
    } else {
      if(last_occurence_room > -1) { //person is in a room
        if(status == 'A') { //can't arrive anywhere without leaving a room
          printf("invalid: can't arrive without leaving a room\n");
          rewind(file);
          fwrite(file_data, 1, file_size, file);
          fclose(file);
          exit(255);
        } 
        /*person is leaving the room*/
        if(last_occurence_room == room_num) {
          leaving_room = 1;
        } else {
          /*leaving different room numbers*/
          printf("invalid: leaving different room numbers\n");
          rewind(file);
          fwrite(file_data, 1, file_size, file);
          fclose(file);
          exit(255);
        }
        
      } else { //person is in the gallery or left the gallery
        if(status == 'A') {
          if(last_occurence_status == 'A' && room_num == -1) { //person is entering the gallery without leaving
            printf("invalid: can't enter gallery without leaving gallery\n");
            rewind(file);
            fwrite(file_data, 1, file_size, file);
            fclose(file);
            exit(255);
          } 
        } else {
          /*person leaving gallery*/
          if(room_num > -1) {
            printf("invalid: can't leave a room when you're in(or not in) the gallery\n");
            rewind(file);
            fwrite(file_data, 1, file_size, file);
            fclose(file);
            exit(255);
          } 

          if(last_occurence_status == 'L') {
            printf("invalid: already left gallery\n");
            rewind(file);
            fwrite(file_data, 1, file_size, file);
            fclose(file);
            exit(255);
          }

          //leaving_gallery = 1;
        }
      } 
    }

    /*attach the new entry if its valid*/
    fprintf(file, "%s\n", entry);

    if(leaving_room == 1) { //person is back in the gallery
      memset(entry, '\0', sizeof entry);
      room_num = -1;
      status = 'A';
      sprintf(entry, "%s %ld %c %c %ld", name, t_num, status, role, room_num);
      //printf("entry leaving room: %s\n", entry);
      fprintf(file, "%s\n", entry);
    }

    /*attach the new time log if entry is valid*/
    rewind(file);
    fprintf(file, "%ld", t_num);
    //printf("entry: %s\n", entry);
  
  fseek(file, 0L, SEEK_END);
  int new_data_size = ftell(file);
  fseek(file, 0L, SEEK_SET);

  unsigned char *new_data = malloc(new_data_size + 10);

  fread(new_data, sizeof *new_data, new_data_size, file);

  //printf("New_data: %s\n", new_data);
  FILE *dummy = fopen("dummy.txt", "w+");
    fprintf(dummy, "%s", new_data);
    //rewind(logpath);
    rewind(dummy);
    fclose(dummy);
    

  //printf("filedata:\n%s", new_data);

    int enc = encrypt_log(new_data, new_data_size, pass, iv, ciphertext);
    
    fseek(file, 0L, SEEK_SET);
    fwrite(ciphertext, 1, enc, file);
  }

  fclose(file);


  return 0;
}
