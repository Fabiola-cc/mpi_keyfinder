#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>
#include <ctype.h>

#define DEFAULT_MAX_KEY ((1UL<<24) - 1)  // cambiar si quieres buscar más (CUIDADO: puede ser enorme)

void decrypt(long key, char *ciph, int len){
  long k = 0;
  long tmp = key;
  for(int i=0; i<8; ++i){
    tmp <<= 1;
    k += (tmp & (0xFELL << (i*8)));
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
  long tmp = key;
  for(int i=0; i<8; ++i){
    tmp <<= 1;
    k += (tmp & (0xFELL << (i*8)));
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

char search_str[] = " the ";

int tryKey(long key, const unsigned char *ciph, int len){
  // hacemos copia porque decrypt muta el buffer
  char *temp = malloc(len + 1);
  if(!temp) return 0;
  memcpy(temp, ciph, len);
  temp[len] = 0;

  decrypt(key, temp, len);

  int found = (strstr((char *)temp, search_str) != NULL);
  free(temp);
  return found;
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
  printf("  Bruteforce:   mpirun -np N %s -b \"cipher_hex\" [-m MAX_KEY]\n", prog);
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

  if(argc < 2){
    if(id == 0) print_usage(argv[0]);
    MPI_Finalize();
    return 1;
  }

  if(strlen(argv[1]) < 2){
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
  else if(mode == 'b'){ // bruteforce
    unsigned char cipher[4096];
    int len = 0;
    unsigned long max_key = DEFAULT_MAX_KEY;

    if(id == 0){
      // parse args in root
      if(argc < 3){
        print_usage(argv[0]);
        MPI_Abort(comm, 1);
      }
      len = hex_to_bytes(argv[2], cipher);
      if(len < 0){
        printf("Error: formato hexadecimal inválido\n");
        MPI_Abort(comm, 1);
      }
      // optional -m MAX
      if(argc >= 5 && strcmp(argv[3], "-m") == 0){
        max_key = strtoul(argv[4], NULL, 10);
      }
      printf("Rank 0: iniciando bruteforce hasta %lu (cada rank intenta pasos de %d)\n", max_key, N);
    }

    // difundir len y max_key
    MPI_Bcast(&len, 1, MPI_INT, 0, comm);
    MPI_Bcast(&max_key, 1, MPI_UNSIGNED_LONG, 0, comm);
    // difundir ciphertext bytes
    MPI_Bcast(cipher, len, MPI_UNSIGNED_CHAR, 0, comm);

    // búsqueda distribuida
    long found_local = -1;
    for(unsigned long key = (unsigned long)id; key <= max_key; key += (unsigned long)N){
      if(tryKey((long)key, cipher, len)){
        found_local = (long)key;
        break;
      }
      // opcional: pequeño checkpoint cada X iteraciones para no saturar
    }

    long found_global = -1;
    MPI_Allreduce(&found_local, &found_global, 1, MPI_LONG, MPI_MAX, comm);

    if(found_global != -1){
      if(id == 0){
        printf("==> Llave encontrada: %ld\n", found_global);
        // mostrar mensaje desencriptado con la llave encontrada
        char *temp = malloc(len + 1);
        memcpy(temp, cipher, len);
        temp[len] = 0;
        decrypt(found_global, temp, len);
        printf("Mensaje desencriptado: %s\n", temp);
        free(temp);
      }
    } else {
      if(id == 0){
        printf("No se encontró la llave en el rango 0..%lu\n", max_key);
      }
    }
  }
  else {
    if(id == 0) print_usage(argv[0]);
  }

  MPI_Finalize();
  return 0;
}
