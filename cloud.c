#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#include"bitadder.h"
#define COUNT 9
#define BLEN 16
LweSample* tmps;
LweSample* tmps1;



void subtract(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    
    
    //initialize the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);

    //run the elementary comparator gate n times
      
  
    for (int i=0; i<nb_bits; i++) 
        {
        compare_bit(&result[i], &a[i], &b[i], &tmps[0], &tmps[1], bk);
         
       }
 
    
  }

void subtract1(LweSample* result1, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
   
    //printf("adder funcrion");
    //initialize the carry to 0
    bootsCONSTANT(&tmps1[0], 0, bk);

    //run the elementary comparator gate n times
        
    for (int i=0; i<nb_bits; i++) 
        {
        compare_bit(&result1[i], &a[i], &b[i], &tmps1[0], &tmps1[1], bk);
         
       }
 
    //delete_gate_bootstrapping_ciphertext_array(2, tmps1);     
    
   
  }


struct ciphertext
 {
  LweSample* ciphertext1;
  LweSample* ciphertext2;
 };
struct ciphertext ciphertext[COUNT];
struct store
 {
  LweSample* mark;
  LweSample* value;
 };
struct store store[COUNT];
int main() {
    
    printf("reading the key...\n");

    //reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
 
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;

    printf("reading the input...\n");
   
     tmps = new_gate_bootstrapping_ciphertext_array(2, params);
     tmps1 = new_gate_bootstrapping_ciphertext_array(2, params);
 	printf("checkpoint 1");
	// initialize cloud ciphertext
	for(int i=0;i<COUNT;i++)
	{
	ciphertext[i].ciphertext1=new_gate_bootstrapping_ciphertext_array(BLEN,params);
	ciphertext[i].ciphertext2=new_gate_bootstrapping_ciphertext_array(BLEN,params);
	}
    //read the ciphertexts from the cloud file
     FILE* cloud_data = fopen("cloud.data","rb");
    for (int k=0;k<COUNT;k++){
    printf("inside cipher block k=%d",k);
    for (int n=0;n<BLEN;n++){
	printf("inside bit block n=%d",n);
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext[k].ciphertext1[n], params);
    	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext[k].ciphertext2[n], params);
	}
    }
	printf("checkpoint 2");
    fclose(cloud_data);
    //read the ciphertexts from the query file
    LweSample* ciphertext_input = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    FILE* query_data = fopen("query.data","rb");
    for (int i=0; i<BLEN; i++) {
        import_gate_bootstrapping_ciphertext_fromFile(query_data, &ciphertext_input[i], params);
    }
    fclose(query_data);
    printf("doing equality check!");
  //equality check
    LweSample* result = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* result1 = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* ans= new_gate_bootstrapping_ciphertext_array(1,params);
    LweSample* complement = new_gate_bootstrapping_ciphertext_array(1,params); 

	// initialize the result structure array // 
	for(int i=0;i<COUNT;i++)
	{
	store[i].mark=new_gate_bootstrapping_ciphertext_array(1,params);
	store[i].value=new_gate_bootstrapping_ciphertext_array(BLEN,params);
	}
        time_t start_time = clock();

	for(int i=0;i<COUNT;i++){

        subtract(result, ciphertext[i].ciphertext1, ciphertext_input,BLEN,bk);
	printf("subtract 1");

        subtract1(result1,ciphertext_input,ciphertext[i].ciphertext1,BLEN,bk); 
	printf("subtract 2");
         bootsOR(ans,tmps,tmps1,bk);
         bootsNOT(complement,ans,bk);
	bootsCOPY(&store[i].mark[0],&complement[0],bk);
	for(int j=0;j<16;j++){ 
	bootsCOPY(&store[i].value[j],&ciphertext[i].ciphertext2[j],bk);
	}

	}
          
          time_t end_time = clock();

    //printf("......computation of the 16 binary + 32 mux gates took: %ld microsecs\n",end_time-start_time);

    //export the answer to a file (for the cloud)
  FILE* answer_data = fopen("answer.data","wb");
	for(int j=0;j<COUNT;j++){
	export_gate_bootstrapping_ciphertext_toFile(answer_data, &store[j].mark[0],params);
     	for(int n=0;n<BLEN;n++)
     	 {
     	 
     	 export_gate_bootstrapping_ciphertext_toFile(answer_data, &store[j].value[n],params);
     	 }
  }
    
//export_gate_bootstrapping_ciphertext_toFile(answer_data, ans, params);
	
		

    	fclose(answer_data);

    //clean up all pointers
    for(int i=0;i<COUNT;i++)
	{
     	delete_gate_bootstrapping_ciphertext_array(BLEN,ciphertext[i].ciphertext1);
     	delete_gate_bootstrapping_ciphertext_array(BLEN,ciphertext[i].ciphertext2);
	}
    for(int i=0;i<COUNT;i++)
	{ 
	delete_gate_bootstrapping_ciphertext_array(1,store[i].mark);
     	delete_gate_bootstrapping_ciphertext_array(BLEN,store[i].value);
     	}
  	delete_gate_bootstrapping_ciphertext_array(BLEN,ciphertext_input);
   	delete_gate_bootstrapping_ciphertext_array(2, tmps);
    	delete_gate_bootstrapping_ciphertext_array(2, tmps1);
    	delete_gate_bootstrapping_ciphertext_array(BLEN, result);
   	delete_gate_bootstrapping_ciphertext_array(BLEN, result1);
    	delete_gate_bootstrapping_cloud_keyset(bk);
	delete_gate_bootstrapping_ciphertext_array(1, complement);
	delete_gate_bootstrapping_ciphertext_array(1, ans);

return 0;

}

   





