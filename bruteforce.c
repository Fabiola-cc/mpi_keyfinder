//bruteforce.c
//Versión mejorada: puede encriptar, desencriptar
//Compilar: mpicc -o des_cipher bruteforce.c -lssl -lcrypto
//Uso: 


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>
#include <ctype.h>

void decrypt(long key, char *ciph, int len){
  long k = 0;
  for(int i=0; i<8; ++i){
    key <<= 1;
    k += (key & (0xFE << i*8));
  }
  
  DES_cblock keyblock;
  DES_key_schedule schedule;
  
  memcpy(&keyblock, &k, 8);
  DES_set_odd_parity(&keyblock);
  DES_set_key_unchecked(&keyblock, &schedule);
  
  for(int i=0; i<len; i+=8){
    DES_ecb_encrypt((DES_cblock *)(ciph + i), 
                    (DES_cblock *)(ciph + i), 
                    &schedule, 
                    DES_DECRYPT);
  }
}

void encrypt(long key, char *ciph, int len){
  long k = 0;
  for(int i=0; i<8; ++i){
    key <<= 1;
    k += (key & (0xFE << i*8));
  }
  
  DES_cblock keyblock;
  DES_key_schedule schedule;
  
  memcpy(&keyblock, &k, 8);
  DES_set_odd_parity(&keyblock);
  DES_set_key_unchecked(&keyblock, &schedule);
  
  for(int i=0; i<len; i+=8){
    DES_ecb_encrypt((DES_cblock *)(ciph + i), 
                    (DES_cblock *)(ciph + i), 
                    &schedule, 
                    DES_ENCRYPT);
  }
}

char search[] = " the ";

int tryKey(long key, char *ciph, int len){
  char temp[len+1];
  memcpy(temp, ciph, len);
  temp[len]=0;
  decrypt(key, temp, len);
  return strstr((char *)temp, search) != NULL;
}

void print_hex(unsigned char *data, int len){
  for(int i=0; i<len; i++){
    printf("%02x", data[i]);
  }
  printf("\n");
}

int hex_to_bytes(const char *hex, unsigned char *bytes){
  int len = strlen(hex);
  if(len % 2 != 0) return -1;
  
  for(int i=0; i<len; i+=2){
    sscanf(hex + i, "%2hhx", &bytes[i/2]);
  }
  return len/2;
}

void do_encrypt(const char *message, long key){
  int len = strlen(message);
  int padded_len = ((len + 7) / 8) * 8;
  
  char *padded = calloc(padded_len + 1, 1);
  strcpy(padded, message);
  
  encrypt(key, padded, padded_len);
  
  printf("Mensaje encriptado (hex): ");
  print_hex((unsigned char *)padded, padded_len);
  
  printf("Key usada: %ld\n", key);
  free(padded);
}

void do_decrypt(const char *cipher_hex, long key){
  unsigned char cipher[1024];
  int len = hex_to_bytes(cipher_hex, cipher);
  
  if(len < 0){
    printf("Error: formato hexadecimal inválido\n");
    return;
  }
  
  char *temp = malloc(len + 1);
  memcpy(temp, cipher, len);
  temp[len] = 0;
  
  decrypt(key, temp, len);
  
  printf("Mensaje desencriptado: %s\n", temp);
  printf("Key usada: %ld\n", key);
  free(temp);
}

void print_usage(const char *prog){
  printf("Uso:\n");
  printf("  Encriptar:    mpirun -np 1 %s -e \"mensaje\" -k KEY\n", prog);
  printf("  Desencriptar: mpirun -np 1 %s -d \"cipher_hex\" -k KEY\n", prog);
  printf("\nEjemplos:\n");
  printf("  %s -e \"Hello the world\" -k 123456\n", prog);
  printf("  %s -d \"6cf5413f7dc89642\" -k 123456\n", prog);
  printf("  mpirun -np 4 %s -b \"6cf5413f7dc89642\"\n", prog);
}

int main(int argc, char *argv[]){
  int N, id;
  MPI_Comm comm = MPI_COMM_WORLD;
  
  MPI_Init(&argc, &argv);
  MPI_Comm_size(comm, &N);
  MPI_Comm_rank(comm, &id);
  
  if(argc < 3){
    if(id == 0) print_usage(argv[0]);
    MPI_Finalize();
    return 1;
  }
  
  char mode = argv[1][1];
  
  if(mode == 'e' && argc == 5 && strcmp(argv[3], "-k") == 0){
    if(id == 0){
      long key = atol(argv[4]);
      do_encrypt(argv[2], key);
    }
  }
  else if(mode == 'd' && argc == 5 && strcmp(argv[3], "-k") == 0){
    if(id == 0){
      long key = atol(argv[4]);
      do_decrypt(argv[2], key);
    }
  }
  
  MPI_Finalize();
  return 0;
}