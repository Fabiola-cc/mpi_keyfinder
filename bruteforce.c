#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>
#include <ctype.h>

#define DEFAULT_MAX_KEY ((1UL<<24) - 1)  // cambiar si quieres buscar más (CUIDADO: puede ser enorme)
#define TIMEOUT_SECONDS 60.0  // Timeout de 1 minuto
#define PROGRESS_INTERVAL 100000  // Reportar cada 100k claves

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

char search_str[] = " es una prueba de ";

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
      printf("╔════════════════════════════════════════════════════════════════╗\n");
      printf("║          BÚSQUEDA DE CLAVE POR FUERZA BRUTA - NAIVE           ║\n");
      printf("╚════════════════════════════════════════════════════════════════╝\n");
      printf("Rango de búsqueda: 0 a %lu\n", max_key);
      printf("Número de procesos: %d\n", N);
      printf("Timeout: %.0f segundos\n", TIMEOUT_SECONDS);
      printf("Palabra clave a buscar: \"%s\"\n", search_str);
      printf("\nIniciando búsqueda...\n\n");
    }

    // difundir len y max_key
    MPI_Bcast(&len, 1, MPI_INT, 0, comm);
    MPI_Bcast(&max_key, 1, MPI_UNSIGNED_LONG, 0, comm);
    // difundir ciphertext bytes
    MPI_Bcast(cipher, len, MPI_UNSIGNED_CHAR, 0, comm);

    // Sincronizar todos los procesos antes de empezar
    MPI_Barrier(comm);
    
    // Iniciar cronómetro
    double start_time = MPI_Wtime();
    double current_time;

    // búsqueda distribuida con timeout y progreso
    long found_local = -1;
    unsigned long keys_tested = 0;
    int timeout_reached = 0;

    for(unsigned long key = (unsigned long)id; key <= max_key; key += (unsigned long)N){
      // Verificar timeout
      current_time = MPI_Wtime();
      if((current_time - start_time) > TIMEOUT_SECONDS){
        timeout_reached = 1;
        if(id == 0){
          printf("\n TIMEOUT alcanzado (%0.f segundos)\n", TIMEOUT_SECONDS);
        }
        break;
      }

      // Probar la clave
      if(tryKey((long)key, cipher, len)){
        found_local = (long)key;
        break;
      }
      
      keys_tested++;

      // Reportar progreso cada PROGRESS_INTERVAL claves
      if(keys_tested % PROGRESS_INTERVAL == 0){
        double elapsed = current_time - start_time;
        double rate = (keys_tested * N) / elapsed;
        double progress = ((double)key / max_key) * 100.0;
        
        printf("[Rank %d] Clave actual: %lu | Progreso: %.2f%% | Velocidad: %.0f claves/seg | Tiempo: %.2fs\n", 
               id, key, progress, rate, elapsed);
      }
    }

    // Obtener tiempo final
    double end_time = MPI_Wtime();
    double total_time = end_time - start_time;

    // Recolectar resultados
    long found_global = -1;
    MPI_Allreduce(&found_local, &found_global, 1, MPI_LONG, MPI_MAX, comm);

    // Recolectar total de claves probadas
    unsigned long total_keys_tested;
    MPI_Reduce(&keys_tested, &total_keys_tested, 1, MPI_UNSIGNED_LONG, MPI_SUM, 0, comm);

    // Verificar si algún proceso alcanzó timeout
    int global_timeout;
    MPI_Allreduce(&timeout_reached, &global_timeout, 1, MPI_INT, MPI_MAX, comm);

    if(id == 0){
      printf("\n╔════════════════════════════════════════════════════════════════╗\n");
      printf("║                         RESULTADOS                             ║\n");
      printf("╚════════════════════════════════════════════════════════════════╝\n");
      
      if(found_global != -1){
        printf("✓ ¡CLAVE ENCONTRADA: %ld!\n\n", found_global);
        
        // mostrar mensaje desencriptado con la llave encontrada
        char *temp = malloc(len + 1);
        memcpy(temp, cipher, len);
        temp[len] = 0;
        decrypt(found_global, temp, len);
        printf("Mensaje desencriptado:\n\"%s\"\n\n", temp);
        free(temp);
      } else {
        if(global_timeout){
          printf("✗ Tiempo agotado - No se encontró la clave en %0.f segundos\n\n", TIMEOUT_SECONDS);
        } else {
          printf("✗ No se encontró la clave en el rango 0..%lu\n\n", max_key);
        }
      }

      printf("Estadísticas:\n");
      printf("  Total de claves probadas: %lu\n", total_keys_tested);
      printf("  Tiempo total: %.2f segundos\n", total_time);
      printf("  Velocidad promedio: %.0f claves/segundo\n", 
             total_time > 0 ? total_keys_tested / total_time : 0.0);
      printf("  Porcentaje explorado: %.4f%%\n", 
             ((double)total_keys_tested / max_key) * 100.0);
      printf("╚════════════════════════════════════════════════════════════════╝\n");
    }
  }
  else {
    if(id == 0) print_usage(argv[0]);
  }

  MPI_Finalize();
  return 0;
}