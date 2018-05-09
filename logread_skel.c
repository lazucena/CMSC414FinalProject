#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define SIZE 1024

int decrypt_log(unsigned char *input, int inlen, unsigned char *key, 
  unsigned char *iv, unsigned char *msgtxt) {

  int i = 0, keyfound = 1, outlen, msglen;
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


int main(int argc, char *argv[]) {
  int   opt, t_num;
  char  *logpath = NULL;
  char pass[SIZE], name[SIZE], entry[SIZE], tempStr[SIZE], room[11], file_txt[4096];
  char role, status, tempRole;
  char *token, tempName[SIZE];
  int readState = 0, nameState = 0, count = 0, eCount = 0, gCount = 0, rCount = 0, roomFound = 0, i;
  int nameFound = 0;
  FILE *file;
  unsigned char iv[1024] = "02346378adehgfhl", ciphertext[1024];

  // Switch cases
  while ((opt = getopt(argc, argv, "K:ISRTE:G:")) != -1) {
    switch(opt) {
      // Time Case
      case 'T':
        printf("unimplemented\n");
        exit(255);
        break;

      // Unimplemented Case
      case 'I':
        printf("unimplemented\n");
        exit(255);
        break;

      // Token Case
      case 'K':
        strcpy(pass, argv[optind - 1]);

        for(i = 0; i < strlen(pass); i++) {
          if(!isalpha(pass[i]) && !isdigit(pass[i])) {
            printf("invalid\n");
            exit(255);
          }
        }

        printf("pass: %s\n", pass);
        break;

      // State Case
      case 'S':
        if (readState != 0) {
          printf("invalid\n");
          exit(255);
        }
        readState = 1;
        break;

      // Room List Case
      case 'R':
        if (readState != 0) {
          printf("invalid\n");
          exit(255);
        }

        readState = 2;
        break;

      // Employee Case
      case 'E':
        role = 'E';
        strcpy(name, argv[optind - 1]);

        for(i = 0; i < strlen(name); i++) {
          if(!isalpha(name[i])) {
            printf("invalid\n");
            exit(255);
          }
        }

        if(nameState == 1) {
          printf("invalid\n");
          exit(255);
        }
        nameState = 1;
        break;

      // Guest Case
      case 'G':
        role = 'G';
        strcpy(name, argv[optind - 1]);

        for(i = 0; i < strlen(name); i++) {
          if(!isalpha(name[i])) {
            printf("invalid\n");
            exit(255);
          }
        }

        if(nameState == 1) {
          printf("invalid\n");
          exit(255);
        }
        nameState = 1;
        break;

      default:
        printf("uknown option\n");
        exit(255);
        break;
    }
  }

  if(optind < argc) {
    logpath = argv[optind];
  }

  // Open File
  if((file = fopen(logpath, "r")) == NULL) {
    printf("integrity violation\n");
    exit(255);
  }

  fseek(file, 0L, SEEK_END);
  int fsize = ftell(file);
  fseek(file, 0L, SEEK_SET);

  char fileRead[fsize][SIZE];

  unsigned char *file_data = malloc(fsize);
  fread(file_data, sizeof *file_data, fsize, file);
  int dec = decrypt_log(file_data, fsize, pass, iv, file_txt);

  if(dec == 0) {
    printf("invalid (decryption)\n");
    fclose(file);
    exit(255);
  }

  fclose(file);

  if((file = fopen(logpath, "w+")) == NULL) {
    printf("integrity violation\n");
    exit(255);
  }

  fprintf(file, "%s", file_txt);
  rewind(file);

  int skip;
  fscanf(file, "%d\n", &skip);

  // State Case Function
  if(readState == 1) {

    char eArray[fsize][SIZE], gArray[fsize][SIZE];
    char roomArr[fsize][SIZE];
    char eLine[SIZE], gLine[SIZE], rLine[SIZE];
    memset(roomArr, '\0', sizeof roomArr);
    rewind(file);

    if(fgets(entry, sizeof(entry), file) == NULL) {
      printf("invalid\n");
      rewind(file);
      fwrite(file_data, 1, fsize, file);
      fclose(file);
      exit(255);
    }

    while(fgets(fileRead[count], SIZE, file) != NULL) {
      fileRead[count][strlen(fileRead[count]) - 1] = '\0';
      sscanf(fileRead[count], "%s %d %c %c %s", tempName, &t_num, &status, &tempRole, room);

      strncpy(name, tempName, strlen(tempName));

      if(tempRole == 'E') {
        if (status == 'A') {
          for(i = 0; i < eCount; i++) {
           if(strcmp(tempName, eArray[i]) == 0) {
             nameFound = 1;
             break;
           }
           if(strcmp(tempName, eArray[i]) < 0) {
             strncpy(tempStr, eArray[i], strlen(eArray[i]));
             strncpy(eArray[i], tempName, strlen(tempName));
             strncpy(tempName, tempStr, strlen(tempStr));
           }
         }
         if(nameFound == 0) {
           strncpy(eArray[eCount], tempName, strlen(tempName));
           eCount++;
         }
         nameFound = 0;
       }
       else {
        for(i = 0; i < eCount; i++) {
          if(strcmp(eArray[i], name) == 0) {
            int j;
            if((i + 1) == eCount) {
              strcpy(eArray[i], "");
            }
            else {
              j = i;
              while((j + 1) != eCount) {
                strncpy(eArray[j], eArray[j + 1], strlen(eArray[j + 1]));
                j = j + 1;
              }
              strcpy(eArray[j], "");
            }
          }
        }
       }
      }
      else {
        if(status == 'A') {
          for(i = 0; i < gCount; i++) { 
            if(strcmp(tempName, gArray[i]) ==0) {
             nameFound = 1;
             break;
           }
           if(strcmp(tempName, gArray[i]) < 0) {
             strncpy(tempStr, gArray[i], strlen(gArray[i]));
             strncpy(gArray[i], tempName, strlen(tempName));
             strncpy(tempName, tempStr, strlen(tempStr));            
           }
         }
         if(nameFound == 0) {
           strncpy(gArray[gCount], tempName, strlen(tempName));
           gCount++;
         }
         nameFound = 0;
       }
       else {
        for(i = 0; i < gCount; i++) {
          if(strcmp(gArray[i], name) == 0) {
            int j;
            if((i + 1) == gCount) {
              strcpy(gArray[i], "");
            }
            else {
              j = i;
              while((j + 1) != gCount) {
                strncpy(gArray[j], gArray[j + 1], strlen(gArray[j + 1]));
                j = j + 1;
              }
              strcpy(gArray[j], "");
            }
          }
        }
       }
     }

      if(strcmp(room, "-1") != 0) {

        strncpy(tempStr, name, strlen(name));

        if(rCount == 0) {
          printf("here\n");
          strncpy(roomArr[0], room, strlen(room));
          strcat(roomArr[0], " ");
          strcat(roomArr[0], tempStr);
          rCount++;
        }
        else {
          if(status == 'A') {
            for(i = 0; i < rCount; i++) {
              token = strtok(roomArr[i], " ");
             if(strcmp(token, room) == 0) {
               char tempRoom[SIZE];
               memset(tempRoom, '\0', SIZE);
               strncpy(tempRoom, token, strlen(token)); 
               token = strtok(NULL, " ");
                // Sort order of names in room
               while(token != NULL) {
                 if(strcmp(tempStr, token) < 0) {
                   strcat(tempRoom, " ");
                   strcat(tempRoom, tempStr);
                   strncpy(tempStr, token, strlen(token));
                 }
                 else {
                   strcat(tempRoom, " ");
                   strcat(tempRoom, token);
                 }
                 token = strtok(NULL, " ");
               }
               strcat(tempRoom, " ");
               strcat(tempRoom, tempStr);
               strncpy(roomArr[i], tempRoom, strlen(tempRoom));
               roomFound = 1;
             }
           }
           if(roomFound == 0) {
             char tempRoom[1024];
             int num, tempNum;
             num = atoi(room);
             strncpy(tempRoom, room, strlen(room));
             strcat(tempRoom, " ");
             strcat(tempRoom, tempStr);
             for(i = 0; i < rCount; i++) {
               token = strtok(roomArr[i], " ");
               tempNum = atoi(token);
               if(num < tempNum) {
                 strncpy(tempStr, roomArr[i], strlen(roomArr[i]));
                 strncpy(roomArr[i], tempRoom, strlen(tempRoom));
                 strncpy(tempRoom, tempStr, strlen(tempStr));
                 num = tempNum;
               }
             }
             rCount++;
           }
          }
          else {
            for(i = 0; i < rCount; i++) {
              if(strstr(roomArr[i], room) != NULL) {
                char *result = strstr(roomArr[i], tempStr);
                int positionSt = result - roomArr[i];
                int positionEd = positionSt + strlen(result);

                positionSt--;
                positionEd++;

                while(roomArr[i][positionEd] != '\0') {
                  roomArr[i][positionSt] = roomArr[i][positionEd];
                  roomArr[i][positionEd] = '\0';
                  positionSt++;
                  positionEd++;
                }

                if(strcmp(roomArr[i], room) == 0) {
                  memset(roomArr[i], '\0', SIZE);
                  rCount--;
                  break;
                }
              }
            }
          }
        }
      }
      count++;
    } 
    count = 0;

    // Employee line
    if(eCount > 0) {
      memset(eLine, '\0', SIZE);
      for(i = 0; i < eCount; i++) {
        if(i == 0) {
          strncpy(eLine, eArray[i], strlen(eArray[i]));
        }
        else {
          strcat(eLine, ",");
          strcat(eLine, eArray[i]);
        }
      }
      printf("%s\n", eLine);
    }
    else {
      printf("\n");
    }
    count = 0;

    // Guest Line
    if(gCount > 0) {
      memset(gLine, '\0', SIZE);
      for(i = 0; i < gCount; i++) {
        if(i == 0) {
          strncpy(gLine, gArray[i], strlen(gArray[i]));
        }
        else {
          strcat(gLine, ",");
          strcat(gLine, gArray[i]);
        }
      }
      printf("%s\n", gLine);
    }
    else {
      printf("\n");
    }
    count = 0;

    // Room lines
    if(rCount > 0) {
      memset(rLine, '\0', SIZE);
      for(i = 0; i < rCount; i++) {
        token = strtok(roomArr[i], " ");
        strncpy(rLine, token, strlen(token));
        strcat(rLine, ": ");
        token = strtok(NULL, " ");
        strcat(rLine, token);
        token = strtok(NULL, " ");
        while(token != NULL) {
          strcat(rLine, ",");
          strcat(rLine, token);
          token = strtok(NULL, " ");
        }
        printf("%s\n", rLine);
        memset(rLine, '\0', SIZE * sizeof(char));
      }
    }
    else {
      printf("\n");
    }
  }

  // Room Case Function
  if(readState == 2) {
    fseek(file, 0L, SEEK_END);
    int fsize = ftell(file);
    fseek(file, 0L, SEEK_SET);

    if(fgets(entry, sizeof(entry), file) == NULL) {
      printf("invalid\n");
      exit(255);
    }
    char rooms[1024];
    int check = 0;
    memset(rooms, '\0', 1024 * sizeof(char));

    while(fgets(fileRead[count], SIZE, file) != NULL) {
      fileRead[count][strlen(fileRead[count]) - 1] = '\0';
      sscanf(fileRead[count], "%s %d %c %c %s", tempName, &t_num, &status, &tempRole, room);

      if(strcmp(tempName, name) == 0 && role == tempRole && status == 'A' && strcmp(room, "-1") != 0) {
        if(check == 0) {
          strncpy(rooms, room, strlen(room));
          check = 1;
        }
        else {
          strcat(rooms, ",");
          strcat(rooms, room);
        }
      }
    }

    printf("%s\n", rooms);

  }

  int enc = encrypt_log(file_txt, strlen(file_txt), pass, iv, ciphertext);
  rewind(file);
  fwrite(ciphertext, 1, enc, file);

  fclose(file);

  return 0;
}
