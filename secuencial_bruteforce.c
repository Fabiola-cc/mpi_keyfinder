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
void des_encrypt(unsigned char* plaintext, unsigned char* ciphertext, 
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
    
    // Cifrar todos los bloques de 8 bytes
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(plaintext + i), 
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
                                        uint64_t max_key, 
                                        int ciphertext_len,
                                        double timeout_seconds) {
    BruteForceResult result = {0, 0.0, 0, 0};
    unsigned char* decrypted = (unsigned char*)malloc(ciphertext_len + 1);
    
    printf("\nIniciando búsqueda de fuerza bruta\n");
    printf("Palabra clave a buscar: \"%s\"\n", search_word);
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

// Función para ejecutar pruebas con claves específicas
void run_tests() {
    // Texto largo (se ajustará a múltiplo de 8)
    const char* text_str = "Esta es una prueba de proyecto 2";
    int text_len = strlen(text_str);
    
    // Ajustar a múltiplo de 8 bytes
    int padded_len = ((text_len + 7) / 8) * 8;
    
    unsigned char* plaintext = (unsigned char*)calloc(padded_len + 1, 1);
    unsigned char* ciphertext = (unsigned char*)calloc(padded_len + 1, 1);
    strcpy((char*)plaintext, text_str);
    
    // Palabra clave a buscar
    const char* search_word = "es una prueba de";
    
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
        "Fácil",
        "Media",
        "Difícil"
    };
    
    int num_tests = sizeof(test_keys) / sizeof(test_keys[0]);
    BruteForceResult allResults[num_tests];
    
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║  ATAQUE DE FUERZA BRUTA SECUENCIAL AL ALGORITMO DES          ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\nTEXTO A CIFRAR:\n\"%s\"\n", text_str);
    printf("\nLongitud original: %d bytes\n", text_len);
    printf("Longitud con padding: %d bytes (%d bloques DES)\n", padded_len, padded_len/8);
    printf("Palabra clave a buscar: \"%s\"\n", search_word);
    printf("TIMEOUT: %.0f segundos (%.2f minutos) por prueba\n\n", 
           timeout_seconds, timeout_seconds / 60.0);
    
    // Resultados de todas las pruebas
    printf("EJECUTANDO PRUEBAS...\n");
    printf("===========================================\n");
    
    for (int i = 0; i < num_tests; i++) {
        uint64_t original_key = test_keys[i];
        
        printf("\n╔════════════════════════════════════════════════════════════╗\n");
        printf("║ Prueba %d: Clave %s\n", i + 1, key_names[i]);
        printf("╚════════════════════════════════════════════════════════════╝\n");
        
        printf("Clave original: ");
        print_key(original_key);
        printf(" (decimal: %llu)\n", (unsigned long long)original_key);
        
        // Cifrar con la clave original
        des_encrypt(plaintext, ciphertext, original_key, padded_len);
        printf("Texto cifrado (primeros 32 bytes): ");
        for (int j = 0; j < (padded_len < 32 ? padded_len : 32); j++) {
            printf("%02X", ciphertext[j]);
        }
        if (padded_len > 32) printf("...");
        printf("\n");
        
        // Realizar ataque de fuerza bruta CON TIMEOUT
        BruteForceResult result = brute_force_sequential(ciphertext, search_word,
                                                         original_key, padded_len, 
                                                         timeout_seconds);
        allResults[i] = result;
        
        // Mostrar resultados
        printf("\n--- RESULTADOS ---\n");
        if (result.success) {
            printf("✓ Clave encontrada: ");
            print_key(result.key_found);
            printf(" (decimal: %llu)\n", (unsigned long long)result.key_found);
            
            // Verificar que sea correcta
            unsigned char* verify = (unsigned char*)calloc(padded_len + 1, 1);
            des_decrypt(ciphertext, verify, result.key_found, padded_len);
            verify[padded_len] = '\0';
            
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
    printf("╠═══════════╦══════════════════════╦═══════════════╦══════════════════╦═════════════════════════════════╣\n");
    printf("║   Tipo    ║       Clave          ║ Tiempo (seg)  ║ Claves/segundo   ║  Estado                         ║\n");
    printf("╠═══════════╬══════════════════════╬═══════════════╬══════════════════╬═════════════════════════════════╣\n");
    
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
    
    printf("╚═══════════╩══════════════════════╩═══════════════╩══════════════════╩═════════════════════════════════╝\n");
    printf("\nNota: Timeout configurado en %.0f segundos (%.2f minutos) por prueba\n", 
           timeout_seconds, timeout_seconds / 60.0);
    
    free(plaintext);
    free(ciphertext);
}

// Función principal
int main() {
    // Inicializar generador de números aleatorios
    srand(time(NULL));
    
    printf("\n");
    
    // Ejecutar pruebas
    run_tests();
    
    return 0;
}