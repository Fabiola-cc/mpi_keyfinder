#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>
#include <ctype.h>

#define MAX_TEXT 4096
#define DEFAULT_MAX_KEY ((1L<<56))
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

char search_str[256] = " es una prueba de ";

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
  printf("  Bruteforce:   mpirun -np N %s -b -k KEY -s \"Key Frase to recognize\" -f file_name -m MAX_KEY\n", prog);
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

  // argumentos faltantes
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
    unsigned char *cipher = malloc(MAX_TEXT);
    if (!cipher) { 
        perror("malloc"); 
        MPI_Finalize();
        return 1; 
    }

    int len = 0;
    unsigned long max_key = DEFAULT_MAX_KEY;
    long known_key = 123456L;
    char input_file[256] = "input.txt";

    MPI_Status st;
    MPI_Request req;
    long mylower, myupper;
    long found = -1;  // Inicializar en -1
    int flag = 0;
    double start_time, end_time, current_time;
    unsigned long keys_tested = 0;  // Cambiar a unsigned long
    int timeout_reached = 0;

    if(id == 0){
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
                known_key = atol(argv[++i]);
                if (known_key <= 0) {
                    fprintf(stderr, "Error: La clave debe ser un número positivo\n");
                    MPI_Abort(comm, 1);
                }
            } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
                strncpy(search_str, argv[++i], sizeof(search_str) - 1);
                search_str[sizeof(search_str) - 1] = '\0';
                if (strlen(search_str) == 0) {
                    fprintf(stderr, "Error: La palabra de búsqueda no puede estar vacía\n");
                    MPI_Abort(comm, 1);
                }
            } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
                strncpy(input_file, argv[++i], sizeof(input_file) - 1);
                input_file[sizeof(input_file) - 1] = '\0';
            } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
                max_key = strtoul(argv[++i], NULL, 10);
            }
        }

        if (strlen(search_str) == 0) {
            fprintf(stderr, "Error: Debe proporcionar palabra de búsqueda con -s\n\n");
            MPI_Abort(comm, 1);
        }
    }

    // Broadcast de todos los parámetros
    MPI_Bcast(&known_key, 1, MPI_LONG, 0, comm);
    MPI_Bcast(search_str, 256, MPI_CHAR, 0, comm);
    MPI_Bcast(input_file, 256, MPI_CHAR, 0, comm);
    MPI_Bcast(&max_key, 1, MPI_UNSIGNED_LONG, 0, comm);

    if (id == 0) {
        FILE *f = fopen(input_file, "rb");
        if (!f) {
            fprintf(stderr, "Error: no se pudo abrir %s\n", input_file);
            MPI_Abort(comm, 1);
        }
        len = fread(cipher, 1, MAX_TEXT, f);
        fclose(f);

        if (len % 8 != 0){
            int pad = 8 - (len % 8);
            memset(cipher + len, 0, pad);
            len += pad;
        }

        printf("DES NAIVE BRUTE FORCE MPI\n");
        printf("Clave usada para cifrar: %-30ld\n", known_key);
        printf("Archivo de entrada: %-35s\n", input_file);
        printf("Texto original: %s\n", cipher);
        
        encrypt(known_key, (char*)cipher, len);
        printf("Texto encriptado (primeros 32 bytes): ");
        for(int i = 0; i < (len < 32 ? len : 32); i++){
            printf("%02x", cipher[i]);
        }
        printf("...\n");
    }
    
    // Difundir ciphertext
    MPI_Bcast(&len, 1, MPI_INT, 0, comm);
    MPI_Bcast(cipher, len, MPI_UNSIGNED_CHAR, 0, comm);
    
    if (id == 0) {
        printf("\nRango de búsqueda: 0 a %lu\n", max_key);
        printf("Número de procesos: %d\n", N);
        printf("Timeout: %.0f segundos\n", TIMEOUT_SECONDS);
        printf("Frase clave a buscar: \"%s\"\n", search_str);
        printf("\nIniciando búsqueda...\n\n");
    }

    // Calcular rango de cada proceso
    unsigned long range_per_node = max_key / N;
    mylower = range_per_node * id;
    myupper = range_per_node * (id + 1);
    if(id == N - 1){
        myupper = max_key;  // Último proceso toma el residuo
    }

    printf("Proceso %d: rango [%ld, %ld] - %ld claves\n", 
           id, mylower, myupper, myupper - mylower);

    // Sincronizar antes de empezar
    MPI_Barrier(comm);
    start_time = MPI_Wtime();

    // CRÍTICO: Iniciar recepción no bloqueante
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, 0, comm, &req);

    unsigned long last_report = mylower;

    // Búsqueda con condición correcta
    for(unsigned long key = mylower; key < myupper && found == -1; key++){
        
        // Verificar timeout
        current_time = MPI_Wtime();
        if((current_time - start_time) > TIMEOUT_SECONDS){
            timeout_reached = 1;
            if(id == 0){
                printf("\n⏰ TIMEOUT alcanzado (%.0f segundos)\n", TIMEOUT_SECONDS);
            }
            break;
        }

        // Probar la clave
        if(tryKey((long)key, cipher, len)){
            found = key;
            printf("\n✓ Proceso %d ENCONTRÓ LA CLAVE: %ld\n", id, key);
            
            // Notificar a todos los demás procesos
            for(int node = 0; node < N; node++){
                if(node != id){
                    MPI_Send(&found, 1, MPI_LONG, node, 0, comm);
                }
            }
            break;
        }
        
        keys_tested++;

        // Verificar si otro proceso encontró la clave (cada 10k iteraciones)
        if(keys_tested % 10000 == 0){
            MPI_Test(&req, &flag, &st);
            if(flag && found != -1){
                printf("Proceso %d: deteniendo búsqueda (clave encontrada por proceso %d)\n", 
                       id, st.MPI_SOURCE);
                break;
            }
        }

        // Reportar progreso cada PROGRESS_INTERVAL claves (solo proceso 0)
        if(id == 0 && keys_tested % PROGRESS_INTERVAL == 0){
            double elapsed = current_time - start_time;
            unsigned long total_estimate = keys_tested * N;
            double rate = total_estimate / elapsed;
            double progress = ((double)key / max_key) * 100.0;
            
            printf("[Progreso] %.4f%% | %lu claves | %.0f k/s | %.2fs\n", 
                   progress, total_estimate, rate/1000.0, elapsed);
        }
    }

    // Cancelar recepción pendiente
    int test_flag;
    MPI_Test(&req, &test_flag, &st);
    if (!test_flag) {
        MPI_Cancel(&req);
    }
    MPI_Wait(&req, MPI_STATUS_IGNORE);

    end_time = MPI_Wtime();
    double total_time = end_time - start_time;

    // Asegurar que todos tengan la clave encontrada
    MPI_Bcast(&found, 1, MPI_LONG, 0, comm);

    // Recolectar estadísticas
    unsigned long total_keys_tested;
    MPI_Reduce(&keys_tested, &total_keys_tested, 1, MPI_UNSIGNED_LONG, MPI_SUM, 0, comm);
    
    int global_timeout;
    MPI_Allreduce(&timeout_reached, &global_timeout, 1, MPI_INT, MPI_MAX, comm);

    if(id == 0){
        printf("\n RESULTADOS \n");
        
        if(found != -1){
            printf("✓ ¡CLAVE ENCONTRADA: %ld!\n\n", found);
            
            // Descifrar y mostrar mensaje
            char *temp = malloc(len + 1);
            if(temp){
                memcpy(temp, cipher, len);
                temp[len] = 0;
                decrypt(found, temp, len);
                printf("Mensaje desencriptado:\n\"%s\"\n\n", temp);
                free(temp);
            }
        } else {
            if(global_timeout){
                printf("✗ Tiempo agotado - No se encontró la clave en %.0f segundos\n\n", 
                       TIMEOUT_SECONDS);
            } else {
                printf("✗ No se encontró la clave en el rango 0..%lu\n\n", max_key);
            }
        }

        printf("Estadísticas:\n");
        printf("  Total de claves probadas: %lu\n", total_keys_tested);
        printf("  Tiempo total: %.2f segundos\n", total_time);
        printf("  Velocidad promedio: %.0f claves/segundo\n", 
               total_time > 0 ? total_keys_tested / total_time : 0.0);
        printf("  Porcentaje explorado: %.6f%%\n", 
               ((double)total_keys_tested / max_key) * 100.0);
    }
    
    free(cipher);
}
  else {
    if(id == 0) print_usage(argv[0]);
  }

  MPI_Finalize();
  return 0;
}