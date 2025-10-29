#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/des.h>
#include <stdint.h>

#define MAX_TEXT 256

// Estructura para almacenar resultados
typedef struct {
    uint64_t key_found;
    double time_elapsed;
    unsigned long long attempts;
    int success;
} BruteForceResult;

// Función para imprimir una clave en formato hexadecimal
void print_key(uint64_t key) {
    printf("0x%016llX", (unsigned long long)key);
}

// Función para imprimir datos en hexadecimal
void print_hex(const char* label, unsigned char* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

// Función para cifrar con DES (múltiples bloques)
void des_encrypt(unsigned char* ciphertext, uint64_t key_value, int len) {
    DES_cblock key;
    DES_key_schedule schedule;
    
    // Convertir key_value a DES_cblock
    for (int i = 0; i < 8; i++) {
        key[i] = (key_value >> (56 - i * 8)) & 0xFF;
    }
    
    // Establecer paridad de bits
    DES_set_odd_parity(&key);
    
    // Crear el schedule de la clave
    DES_set_key_unchecked(&key, &schedule);
    
    // Cifrar todos los bloques de 8 bytes
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(ciphertext + i), 
                        (DES_cblock*)(ciphertext + i), 
                        &schedule, DES_ENCRYPT);
    }
}

// Función para descifrar con DES (múltiples bloques)
void des_decrypt(unsigned char* ciphertext, unsigned char* decrypted, 
                 uint64_t key_value, int len) {
    DES_cblock key;
    DES_key_schedule schedule;
    
    // Convertir key_value a DES_cblock
    for (int i = 0; i < 8; i++) {
        key[i] = (key_value >> (56 - i * 8)) & 0xFF;
    }
    
    // Establecer paridad de bits
    DES_set_odd_parity(&key);
    
    // Crear el schedule de la clave
    DES_set_key_unchecked(&key, &schedule);
    
    // Descifrar todos los bloques de 8 bytes
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(ciphertext + i), 
                        (DES_cblock*)(decrypted + i), 
                        &schedule, DES_DECRYPT);
    }
}

// Función de fuerza bruta secuencial con timeout y búsqueda por palabra clave
BruteForceResult brute_force_sequential(unsigned char* ciphertext, 
                                        const char* search_word,
                                        int ciphertext_len,
                                        double timeout_seconds) {
    BruteForceResult result = {0, 0.0, 0, 0};
    uint64_t max_key = 1L << 24; // Espacio pequeño para pruebas secuenciales
    unsigned char* decrypted = (unsigned char*)malloc(ciphertext_len + 1);
    
    printf("\nIniciando búsqueda de fuerza bruta\n");
    printf("Frase clave a buscar: \"%s\"\n", search_word);
    printf("Espacio de búsqueda: hasta %llu claves\n", (unsigned long long)(max_key + 1));
    printf("Timeout configurado: %.0f segundos (%.2f minutos)\n", 
           timeout_seconds, timeout_seconds / 60.0);
    
    clock_t start = clock();
    
    // Probar todas las claves posibles
    for (uint64_t key = 0; key <= max_key; key++) {
        // Descifrar con la clave actual
        des_decrypt(ciphertext, decrypted, key, ciphertext_len);
        decrypted[ciphertext_len] = '\0';  // Null terminator
        
        result.attempts++;
        
        // Verificar si el texto descifrado contiene la palabra clave
        if (strstr((char*)decrypted, search_word) != NULL) {
            result.key_found = key;
            result.success = 1;
            break;
        }
        
        // Verificar timeout cada 100000 intentos
        if (key > 0 && key % 100000 == 0) {
            clock_t now = clock();
            double elapsed = ((double)(now - start)) / CLOCKS_PER_SEC;
            
            // Verificar si se alcanzó el timeout
            if (elapsed >= timeout_seconds) {
                printf("\nTIMEOUT alcanzado (%.2f segundos)\n", elapsed);
                printf("Claves probadas: %llu de %llu (%.4f%%)\n", 
                       result.attempts, 
                       (unsigned long long)(max_key + 1),
                       (result.attempts * 100.0) / (max_key + 1));
                break;
            }
            
            // Mostrar progreso cada millón de intentos
            if (key % 1000000 == 0) {
                printf("Progreso: %llu claves probadas (%.4f%%) - %.2f seg - %.0f claves/seg\n", 
                       (unsigned long long)key,
                       (key * 100.0) / max_key,
                       elapsed,
                       result.attempts / (elapsed > 0 ? elapsed : 1));
            }
        }
    }
    
    clock_t end = clock();
    result.time_elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    free(decrypted);
    return result;
}

// Función para ejecutar segun parametros
void run_normal_execution(unsigned char* buffer, int ciphlen, char* search_word, long original_key) {
    // TIMEOUT EN SEGUNDOS - Ajusta este valor según necesites
    double timeout_seconds = 60.0;  // 1 minuto por defecto
    
    printf("ATAQUE DE FUERZA BRUTA SECUENCIAL AL ALGORITMO DES\n");
    printf("\nTEXTO A CIFRAR:\n\"%s\"\n", buffer);
    printf("\nLongitud del texto (incluye padding si fue necesario): %d bytes\n", ciphlen);
    printf("Frase clave a buscar: \"%s\"\n", search_word);
    printf("TIMEOUT: %.0f segundos (%.2f minutos) por prueba\n\n", 
           timeout_seconds, timeout_seconds / 60.0);
        
    printf("Clave recibida: ");
    print_key(original_key);
    printf(" (decimal: %llu)\n", (unsigned long long)original_key);

    // Cifrar texto
    des_encrypt(buffer, original_key, ciphlen);
    printf("Texto cifrado (primeros 32 bytes): ");
    for (int j = 0; j < (ciphlen < 32 ? ciphlen : 32); j++) {
        printf("%02X", buffer[j]);
    }
    if (ciphlen > 32) printf("...");
    printf("\n");
        
    // Realizar ataque de fuerza bruta CON TIMEOUT
    BruteForceResult result = brute_force_sequential(buffer, search_word, ciphlen, timeout_seconds);
        
    // Mostrar resultados
    printf("\n RESULTADO \n");
    if (result.success) {
        printf("✓ Clave encontrada: ");
        print_key(result.key_found);
        printf(" (decimal: %llu)\n", (unsigned long long)result.key_found);
        
        // Verificar que sea correcta
        unsigned char* verify = (unsigned char*)calloc(ciphlen + 1, 1);
        des_decrypt(buffer, verify, result.key_found, ciphlen);
        verify[ciphlen] = '\0';
        
        printf("Texto descifrado:\n\"%s\"\n", verify);
        
        if (strstr((char*)verify, search_word) != NULL) {
            printf("✓ Verificación exitosa: texto contiene \"%s\"\n", search_word);
        }
        free(verify);
    } else {
        printf("✗ Clave no encontrada (timeout o rango agotado)\n");
    }
    
    printf("Intentos realizados: %llu\n", result.attempts);
    printf("Tiempo transcurrido: %.6f segundos (%.2f minutos)\n", 
            result.time_elapsed, result.time_elapsed / 60.0);
    
    if (result.time_elapsed > 0) {
        printf("Velocidad: %.2f claves/segundo\n", 
                result.attempts / result.time_elapsed);
    }
    
    printf("\n");
    
    printf("\nNota: Timeout configurado en %.0f segundos (%.2f minutos) por prueba\n", 
           timeout_seconds, timeout_seconds / 60.0);
}

// Función para ejecutar pruebas con claves específicas
void run_tests(unsigned char buffer[], int ciphlen, char search_word[]) {
    // TIMEOUT EN SEGUNDOS - Ajusta este valor según necesites
    double timeout_seconds = 60.0;  // 1 minuto por defecto
    
    // Claves específicas a probar (del proyecto)
    uint64_t test_keys[] = {
        2251799813685248ULL,                 // Muy fácil
        36028797018963969ULL,      // (2^56)/2 + 1 - Fácil
        45035996273704960ULL,      // (2^56)/2 + (2^56)/8 - Media
        15836833854489657ULL       // Difícil
    };
    
    const char* key_names[] = {
        "Extra",
        "Facil",
        "Media",
        "Dificil"
    };
    
    int num_tests = sizeof(test_keys) / sizeof(test_keys[0]);
    BruteForceResult allResults[num_tests];
    
    printf("ATAQUE DE FUERZA BRUTA SECUENCIAL AL ALGORITMO DES\n");
    printf("\nTEXTO A CIFRAR:\n\"%s\"\n", buffer);
    printf("\nLongitud del texto (incluye padding si fue necesario): %d bytes\n", ciphlen);
    printf("Palabra clave a buscar: \"%s\"\n", search_word);
    printf("TIMEOUT: %.0f segundos (%.2f minutos) por prueba\n\n", 
           timeout_seconds, timeout_seconds / 60.0);
    
    // Resultados de todas las pruebas
    printf("EJECUTANDO PRUEBAS...\n");
    
    for (int i = 0; i < num_tests; i++) {
        uint64_t original_key = test_keys[i];
        
        printf("Prueba %d: Clave %s\n", i + 1, key_names[i]);
        
        printf("Clave original: ");
        print_key(original_key);
        printf(" (decimal: %llu)\n", (unsigned long long)original_key);

        // Cifrar con la clave original
        des_encrypt(buffer, original_key, ciphlen);
        printf("Texto cifrado (primeros 32 bytes): ");
        for (int j = 0; j < (ciphlen < 32 ? ciphlen : 32); j++) {
            printf("%02X", buffer[j]);
        }
        if (ciphlen > 32) printf("...");
        printf("\n");
        
        // Realizar ataque de fuerza bruta CON TIMEOUT
        BruteForceResult result = brute_force_sequential(buffer, search_word, ciphlen, timeout_seconds);
        allResults[i] = result;
        
        // Mostrar resultados
        printf("\n RESULTADOS \n");
        if (result.success) {
            printf("✓ Clave encontrada: ");
            print_key(result.key_found);
            printf(" (decimal: %llu)\n", (unsigned long long)result.key_found);
            
            // Verificar que sea correcta
            unsigned char* verify = (unsigned char*)calloc(ciphlen + 1, 1);
            des_decrypt(buffer, verify, result.key_found, ciphlen);
            verify[ciphlen] = '\0';
            
            printf("Texto descifrado:\n\"%s\"\n", verify);
            
            if (strstr((char*)verify, search_word) != NULL) {
                printf("✓ Verificación exitosa: texto contiene \"%s\"\n", search_word);
            }
            free(verify);
        } else {
            printf("✗ Clave no encontrada (timeout o rango agotado)\n");
        }
        
        printf("Intentos realizados: %llu\n", result.attempts);
        printf("Tiempo transcurrido: %.6f segundos (%.2f minutos)\n", 
               result.time_elapsed, result.time_elapsed / 60.0);
        
        if (result.time_elapsed > 0) {
            printf("Velocidad: %.2f claves/segundo\n", 
                   result.attempts / result.time_elapsed);
        }
        
        printf("\n");
    }
    
    // Tabla resumen
    printf("\n\n");
    printf("╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                                   RESUMEN DE PRUEBAS                                                 ║\n");
    printf("╠═══════════╦══════════════════════╦═══════════════╦══════════════════╦════════════════════════════════╣\n");
    printf("║   Tipo    ║       Clave          ║ Tiempo (seg)  ║ Claves/segundo   ║  Estado                        ║\n");
    printf("╠═══════════╬══════════════════════╬═══════════════╬══════════════════╬════════════════════════════════╣\n");
    
    for (int i = 0; i < num_tests; i++) {
        BruteForceResult result = allResults[i];
        const char* status;
        
        if (result.success) {
            status = "✓ Encontrada";
        } else {
            status = "✗ Timeout/No encontrada";
        }
        
        printf("║ %-9s ║ %20llu ║ %13.6f ║ %16.2f ║ %-31s ║\n", 
               key_names[i], 
               (unsigned long long)test_keys[i],
               result.time_elapsed, 
               result.attempts / (result.time_elapsed > 0 ? result.time_elapsed : 1),
               status);
    }
    
    printf("╚═══════════╩══════════════════════╩═══════════════╩══════════════════╩════════════════════════════════╝\n");
    printf("\nNota: Timeout configurado en %.0f segundos (%.2f minutos) por prueba\n", 
           timeout_seconds, timeout_seconds / 60.0);
}

// Función principal
int main(int argc, char *argv[]) {
    // Parámetros configurables
    long known_key = 123456L;
    char search_word[256] = "";
    char input_file[256] = "input.txt";
    int run_tests_flag = 0;

    // Lectura de parámetros
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0) {run_tests_flag = 1;}

        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) { // Llave de cifrado
            known_key = atol(argv[++i]);
            if (known_key <= 0) { // Validación de clave válida
                fprintf(stderr, "Error: La clave debe ser un número positivo\n");
                break;
            }
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) { // Palabras clave a buscar en descifrado
            strncpy(search_word, argv[++i], sizeof(search_word) - 1);
            if (strlen(search_word) == 0) { // Validación de que exita la palabra
                fprintf(stderr, "Error: La palabra de búsqueda no puede estar vacía\n");
                break;
            }
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) { // Archivo con texto a cifrar (opcional)
            strncpy(input_file, argv[++i], sizeof(input_file) - 1);
        }
    }

    // Lectura de archivo con texto a cifrar
    FILE *f = fopen(input_file, "rb");
    if (!f) {
        fprintf(stderr, "Error: no se pudo abrir %s\n", input_file);
        return 1;
    }

    unsigned char *buffer = malloc(MAX_TEXT); // Texto largo (se ajustará a múltiplo de 8)
    if (!buffer) { perror("malloc"); return 1; }

    int ciphlen = fread(buffer, 1, MAX_TEXT, f);
    fclose(f);

    // Ajustar texto a múltiplo de 8 bytes
    if (ciphlen % 8 != 0){
        int pad = 8 - (ciphlen % 8);
        memset(buffer + ciphlen, 0, pad); // inicializar bytes de padding
        ciphlen += pad;
    }

    // Inicializar generador de números aleatorios
    srand(time(NULL));
    printf("\n");

    if (run_tests_flag == 1) {
        run_tests(buffer, ciphlen, search_word);
        free(buffer);
        return 0;
    }

    run_normal_execution(buffer, ciphlen, search_word, known_key);
    free(buffer);
    return 0;
}