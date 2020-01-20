#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#define COUNT 19
#define BLEN 16
int main() {

    //reads the secret key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
 
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    //read the ciphertexts of the result
	LweSample* result = new_gate_bootstrapping_ciphertext_array(BLEN, params);


    //import answer
    FILE* answer_data = fopen("answer.data","rb");
        for(int i=0; i<BLEN; i++){ 
            
	    import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result[i], params);
	}
    
    fclose(answer_data);

    //decrypt and rebuild the answer
    int32_t int_answer=0;
        for(int i=0; i<BLEN; i++){
            int ai = bootsSymDecrypt(&result[i], key)>0;
            int_answer |= (ai<<i);
        }
	
        printf("The answer : %d \n", int_answer);
    
	//printf(" completed!! \n");
	//clean up all pointers
	delete_gate_bootstrapping_ciphertext_array(BLEN, result);
	delete_gate_bootstrapping_secret_keyset(key);

return 0;

}
