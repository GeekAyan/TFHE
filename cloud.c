#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#include"bitadder.h"
#define COUNT 19
#define BLEN 16
LweSample* tmps;
LweSample* tmps1;

void subtract(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    
    bootsCONSTANT(&tmps[0], 0, bk); //initialize the carry to 0

    //run the elementary comparator gate n times//
      
  	for (int i=0; i<nb_bits; i++) {
        compare_bit(&result[i], &a[i], &b[i], &tmps[0], &tmps[1], bk);
        }
}

void subtract1(LweSample* result1, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {

    bootsCONSTANT(&tmps1[0], 0, bk); //initialize the carry to 0

    //run the elementary comparator gate n times//
        
    for (int i=0; i<nb_bits; i++) {
        compare_bit(&result1[i], &a[i], &b[i], &tmps1[0], &tmps1[1], bk);
        }
 
    //delete_gate_bootstrapping_ciphertext_array(2, tmps1);     
    
   
  }
void Addition(LweSample* top1, const LweSample* a6, const LweSample* b6, LweSample* lsb_carry1, LweSample* tmp6, const 	TFheGateBootstrappingCloudKeySet* bk) {
     LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    
    bootsXOR(temp1, a6, b6, bk);  //a xorb  
    bootsXOR(top1,temp1,lsb_carry1,bk);  //a xor b xor ci
    bootsAND(temp2,temp1,lsb_carry1,bk);   //ci and (a xor b)
    bootsAND(temp3,a6,b6,bk);             // a and b 
    bootsOR(tmp6,temp2,temp3,bk);       // a&b + ci*(a xor b)
    bootsCOPY(lsb_carry1,tmp6,bk);


}
void Adder(LweSample* top1, const LweSample* a6, const LweSample* b6, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk)
   {
     LweSample* tmps6 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
     bootsCONSTANT(&tmps6[0], 0, bk); //initialize carry to 0

    //run the elementary comparator gate n times//
        
    for (int i=0; i<nb_bits; i++){
        Addition(&top1[i], &a6[i], &b6[i], &tmps6[0], &tmps6[1], bk);
        }
     delete_gate_bootstrapping_ciphertext_array(2, tmps6);    
   }

void multiplexer(LweSample* rdbdata,LweSample* a,LweSample* b,LweSample* select_line,const int nb_bit, const TFheGateBootstrappingCloudKeySet* bk)
  {
      int m=0;
      for(int i=0;i<nb_bit;i++){
        bootsMUX(&rdbdata[i],&select_line[m],&b[i],&a[i],bk);
        }
  }


struct ciphertext
 {
  LweSample* ciphertext1;
  LweSample* ciphertext2;
 };
struct ciphertext ciphertext[COUNT];
int main() {
    
    printf("Reading the key...\n");

    //reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
 
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;

    printf("Reading the ciphertexts...\n");
   
     tmps = new_gate_bootstrapping_ciphertext_array(2, params);
     tmps1 = new_gate_bootstrapping_ciphertext_array(2, params);
	// initialize cloud ciphertext//
	for(int i=0;i<COUNT;i++)
	{
	ciphertext[i].ciphertext1=new_gate_bootstrapping_ciphertext_array(BLEN,params);
	ciphertext[i].ciphertext2=new_gate_bootstrapping_ciphertext_array(BLEN,params);
	}
   	//read the ciphertexts from the cloud file//
     FILE* cloud_data = fopen("cloud.data","rb");
    	for (int k=0;k<COUNT;k++){
   	for (int n=0;n<BLEN;n++){
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext[k].ciphertext1[n], params);
    	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext[k].ciphertext2[n], params);
	}
    	}
     fclose(cloud_data);
    
    printf("Reading the query data...\n");
    printf("Executing");
	//read the ciphertexts from the query file//
    LweSample* ciphertext_input = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* result_val =  new_gate_bootstrapping_ciphertext_array(BLEN, params);  
    FILE* query_data = fopen("query.data","rb");
    for (int i=0; i<BLEN; i++) {
        import_gate_bootstrapping_ciphertext_fromFile(query_data, &ciphertext_input[i], params);
    }
    fclose(query_data);
    
    LweSample* result = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* result1 = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* ans= new_gate_bootstrapping_ciphertext_array(1,params);
    LweSample* complement = new_gate_bootstrapping_ciphertext_array(1,params); 
    LweSample* enc_th= new_gate_bootstrapping_ciphertext_array(BLEN,params);
    LweSample* f_result= new_gate_bootstrapping_ciphertext_array(BLEN,params);
    LweSample* res_tmp= new_gate_bootstrapping_ciphertext_array(BLEN,params);
// initialize the result flags // 
	 for(int i=0;i<BLEN;i++)
	     {
       		bootsCONSTANT(&enc_th[i],0,bk);
		bootsCONSTANT(&res_tmp[i],0,bk);
    	     }
	
        time_t start_time = clock();
//equality check//
	
	for(int i=0;i<COUNT;i++){
	printf(".");
        subtract(result, ciphertext[i].ciphertext1, ciphertext_input,BLEN,bk);
	subtract1(result1,ciphertext_input,ciphertext[i].ciphertext1,BLEN,bk); 
        bootsOR(ans,tmps,tmps1,bk);
        bootsNOT(complement,ans,bk);
	//Select only the valid result//
        multiplexer(result_val,enc_th,ciphertext[i].ciphertext2,complement,BLEN,bk);
	//Add the valid result to final result//
	Adder(f_result,result_val,res_tmp,BLEN,bk);
	//Change the result temp to final result//
	for(int j=0;j<BLEN;j++){ 
	bootsCOPY(&res_tmp[j],&f_result[j],bk);
	}
	
	}
	
          time_t end_time = clock();

    //printf("......computation of the 16 binary + 32 mux gates took: %ld microsecs\n",end_time-start_time);

    //export the answer to a file (for the cloud)
  	FILE* answer_data = fopen("answer.data","wb");
     	for(int n=0;n<BLEN;n++){
     	 export_gate_bootstrapping_ciphertext_toFile(answer_data, &f_result[n],params);
     	 }
	
	printf("\nExecuted successfully! Time to execute %ld second\n",(end_time-start_time)/1000000);	

    	fclose(answer_data);

    //clean up all pointers
    for(int i=0;i<COUNT;i++)
	{
     	delete_gate_bootstrapping_ciphertext_array(BLEN,ciphertext[i].ciphertext1);
     	delete_gate_bootstrapping_ciphertext_array(BLEN,ciphertext[i].ciphertext2);
	}
  	delete_gate_bootstrapping_ciphertext_array(BLEN,ciphertext_input);
   	delete_gate_bootstrapping_ciphertext_array(2, tmps);
    	delete_gate_bootstrapping_ciphertext_array(2, tmps1);
    	delete_gate_bootstrapping_ciphertext_array(BLEN, result);
   	delete_gate_bootstrapping_ciphertext_array(BLEN, result1);
	delete_gate_bootstrapping_ciphertext_array(BLEN, f_result);
	delete_gate_bootstrapping_ciphertext_array(BLEN, result_val);
    	delete_gate_bootstrapping_cloud_keyset(bk);
	delete_gate_bootstrapping_ciphertext_array(1, complement);
	delete_gate_bootstrapping_ciphertext_array(1, ans);

return 0;

}

   





