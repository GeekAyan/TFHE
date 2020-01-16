#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

struct store
 {
  LweSample* mark;
  LweSample* value;
 };
struct store store[10];
int main() {

    //reads the cloud key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
 
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    //read the ciphertexts of the result
    //LweSample* answer = new_gate_bootstrapping_ciphertext_array(16, params);
    //LweSample* answer[10];
    //LweSample* answer;
    for(int j = 0; j < 10; j++){
    	store[j].mark = new_gate_bootstrapping_ciphertext_array(1, params);
	store[j].value = new_gate_bootstrapping_ciphertext_array(16, params);
	}

    //import answer
    FILE* answer_data = fopen("answer.data","rb");
    for(int j = 0; j < 10; j++){
	import_gate_bootstrapping_ciphertext_fromFile(answer_data, &store[j].mark[0], params);
        for (int i=0; i<16; i++){ 
            
	    import_gate_bootstrapping_ciphertext_fromFile(answer_data, &store[j].value[i], params);
	}
    }
    /* LweSample* input = new_gate_bootstrapping_ciphertext_array(16, params);
    for(int i=0; i < 16; i++){
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &input[i], params);
    } */
    fclose(answer_data);

    //decrypt and rebuild the answer
    int32_t int_answer[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int32_t inputd[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    for(int j = 0; j < 10; j++){
	int aj = bootsSymDecrypt(&store[j].mark[0], key)>0;
        inputd[j] |= aj;
        for (int i=0; i<16; i++) {
            int ai = bootsSymDecrypt(&store[j].value[i], key)>0;
            int_answer[j] |= (ai<<i);
        }
    }
    
    //for(int i = 0; i < 16; i++){
    //    int ai = bootsSymDecrypt(&answer[i], key)>0;
    //    int_answer |= (ai<<i);
    //}
    for(int j = 0; j < 10; j++)
        printf("The mark %d and value %d \n", inputd[j], int_answer[j]);
    //printf("And the result is: %ld\n",int_answer); 

    //clean up all pointers
    //delete_gate_bootstrapping_ciphertext_array(16, answer);	
	printf(" completed!! \n");
    delete_gate_bootstrapping_secret_keyset(key);

}
