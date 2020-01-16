#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#define COUNT 9
#define BLEN 16
struct ciphertext{
  	LweSample* ciphertext1;
  	LweSample* ciphertext2;
};
struct exponent{
	int32_t exp;
	int32_t val;
};

    struct exponent ep[COUNT];
    struct ciphertext ciphertext[COUNT];
int main() {
    //generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
    //struct of numbers

  printf("starting execution..."); 
    
//updating value from file
    char const* const filename="sigmoid.txt";
   FILE *fp=fopen(filename,"r");
printf("File opened!");
int p=0;
/* take input from text file and store in a structure array */
while(fscanf(fp,"%d%d",&ep[p].exp,&ep[p].val)!=EOF)
   {
     p++;
   }
printf("p=%d",p);
for(int i=0;i<p;i++)
{
 printf("\n%d\t%d",ep[i].exp,ep[i].val);

}
fclose(fp);
printf("\nFile closed!");

//struct ciphertext ciphertext[line];
/* initialize the ciphertext structure array*/
for(int i=0;i<COUNT;i++)
{
ciphertext[i].ciphertext1=new_gate_bootstrapping_ciphertext_array(BLEN,params);
ciphertext[i].ciphertext2=new_gate_bootstrapping_ciphertext_array(BLEN,params);
}
/* Encrypt the plaintexts and store in ciphertexts array */
  for (int j=0;j<COUNT;j++)
  {
    for(int n=0;n<BLEN;n++){
      bootsSymEncrypt(&ciphertext[j].ciphertext1[n],(ep[j].exp>>n)&1,key);
	}
    for(int n=0;n<BLEN;n++){
      bootsSymEncrypt(&ciphertext[j].ciphertext2[n],(ep[j].val>>n)&1,key);
      //bootsCOPY(&ciphertext[j].ciphertext2[n],(ep[j].val>>n)&1,key);
     }

  }

    //taking input from the user
    int input;
    printf("\nEnter exponent value:");
    scanf("%d", &input);
    

    //encrypting the input
    LweSample* cipherinput = new_gate_bootstrapping_ciphertext_array(BLEN,params);
    for (int i = 0; i < BLEN; i++){
         bootsSymEncrypt(&cipherinput[i], (input>>i)&1, key);
    }
    
    
    
    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    //export the 32 ciphertexts to a file (for the cloud)
   FILE* cloud_data=fopen("cloud.data","wb");
    
     for(int j=0;j<COUNT;j++){
     for(int n=0;n<BLEN;n++){
      export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[j].ciphertext1[n],params);
      }
    /* for(int n=0;n<64;n++){
      export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[j].ciphertext2[n],params);
      } */
  }
      fclose(cloud_data);
//export the input to cloud
   FILE* query_data=fopen("query.data","wb");
    
     
     for(int n=0;n<BLEN;n++)
      {
      export_gate_bootstrapping_ciphertext_toFile(query_data, &cipherinput[n],params);
      }
 
      fclose(query_data);

    //clean up all pointer
for(int i=0;i<COUNT;i++)
{
     delete_gate_bootstrapping_ciphertext_array(BLEN,ciphertext[i].ciphertext1);
     delete_gate_bootstrapping_ciphertext_array(BLEN,ciphertext[i].ciphertext2);
}
delete_gate_bootstrapping_ciphertext_array(BLEN,cipherinput);
     
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

}
