#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#define COUNT 19
#define BLEN 16


void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp4=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp5=new_gate_bootstrapping_ciphertext_array(1,bk->params);

    bootsXOR(temp1, a, b, bk);  //a xorb
    bootsXOR(result,temp1,lsb_carry,bk);  //a xor b xor ci
    
    bootsNOT(temp4,a,bk);  // complement of a
    bootsAND(temp3,temp4,b,bk); // complement a and b

    bootsNOT(temp5,temp1,bk);  // complement of a XOR b

    bootsAND(temp2,temp5,lsb_carry,bk);// complement of a XOR b AND lasb_carry
  
    bootsOR(tmp,temp2,temp3,bk);       // a&b + ci*(a xor b)
    bootsCOPY(lsb_carry,tmp,bk);
}



void subtract(LweSample* result, LweSample* tmps, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    
    

    //run the elementary comparator gate n times//
      
  	for (int i=0; i<nb_bits; i++) {
        compare_bit(&result[i], &a[i], &b[i], &tmps[0], &tmps[1], bk);
        }
}


void Addition(LweSample* top1, const LweSample* a6, const LweSample* b6, LweSample* lsb_carry1, LweSample* tmp6, const 	TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    
    bootsXOR(temp1, a6, b6, bk);  //a xor b  
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

  void multiply(LweSample* product, LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) 
  {
        
    LweSample* enc_theta=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    for(int i=0;i<nb_bits;i++) //initialize theta to all zero bits
       {
          bootsCONSTANT(&enc_theta[i],0,bk);
       }
    for(int i=0;i<2*nb_bits;i++) //initialize product to all zero bits
       {
          bootsCONSTANT(&product[i],0,bk);
       } 

    for (int i=0; i<nb_bits; i++) {
        LweSample* temp_result=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        LweSample* partial_sum=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        for(int j=0;j<2*nb_bits;j++) //initialize temp_result to all zero bits
        {
          bootsCONSTANT(&temp_result[j],0,bk);
          bootsCONSTANT(&partial_sum[j],0,bk);
        } 
        LweSample* temp2=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
        multiplexer(temp2,enc_theta,a,&b[i],nb_bits,bk);
        for(int j=0;j<nb_bits;j++){ 
          bootsCOPY(&temp_result[i+j],&temp2[j],bk);
        }

        //Add the valid result to partial_sum//
        Adder(partial_sum,product,temp_result,2*nb_bits,bk);
        //Change the partial sum to final product//
        for(int j=0;j<2*nb_bits;j++){ 
         bootsCOPY(&product[j],&partial_sum[j],bk);
        }
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
    LweSample* remainder = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* mux_op = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* mux_tmp = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* mux_op2 = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* mux_tmp2 = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* ans= new_gate_bootstrapping_ciphertext_array(1,params);
    LweSample* complement = new_gate_bootstrapping_ciphertext_array(1,params); 
    LweSample* enc_th= new_gate_bootstrapping_ciphertext_array(BLEN,params);
    LweSample* f_result= new_gate_bootstrapping_ciphertext_array(BLEN,params);
    LweSample* res_tmp= new_gate_bootstrapping_ciphertext_array(BLEN,params);
    LweSample* signbit = new_gate_bootstrapping_ciphertext_array(2, params);;
    LweSample* signbit1= new_gate_bootstrapping_ciphertext_array(2, params);;
// initialize the result flags // 
	 for(int i=0;i<BLEN;i++)
	     {
       		bootsCONSTANT(&enc_th[i],0,bk);
		bootsCONSTANT(&res_tmp[i],0,bk);
		bootsCONSTANT(&mux_tmp[i],0,bk);
		bootsCONSTANT(&mux_tmp2[i],0,bk);
    	     }
	
        time_t start_time = clock();
//Giant steps: compare the 10th digit//

	for(int i=9;i<COUNT;i++){
	bootsCONSTANT(&signbit[0], 0, bk); //initialize the carry to 0
	subtract(result, signbit, ciphertext_input, ciphertext[i].ciphertext1, BLEN,bk);
	multiplexer(mux_op,ciphertext[i].ciphertext1,mux_tmp,signbit,BLEN,bk);
	multiplexer(mux_op2,ciphertext[i].ciphertext2,mux_tmp2,signbit,BLEN,bk);
	
	//store the result in mux tmp
	for(int j=0;j<BLEN;j++){ 
	bootsCOPY(&mux_tmp[j],&mux_op[j],bk);
	bootsCOPY(&mux_tmp2[j],&mux_op2[j],bk);
	}
	}

//subtract to get single digit//
bootsCONSTANT(&signbit[0], 0, bk); //initialize the carry to 0
subtract(remainder,signbit, ciphertext_input, mux_op, BLEN,bk);

	
//Baby steps: equality check//
	
	for(int i=0;i<10;i++){
	printf(".");
	bootsCONSTANT(&signbit[0], 0, bk); //initialize the carry to 0
	bootsCONSTANT(&signbit1[0], 0, bk); //initialize the carry to 0
        subtract(result,signbit, ciphertext[i].ciphertext1, remainder,BLEN,bk);
	subtract(result1,signbit1,remainder,ciphertext[i].ciphertext1,BLEN,bk); 
        bootsOR(ans,signbit,signbit1,bk);
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
	// multiply the two exponent values to get ultimate result
	LweSample* u_result= new_gate_bootstrapping_ciphertext_array(2*BLEN,params);
  multiply(u_result,mux_op2,f_result,BLEN,bk);
	//decrypt and rebuild the answer
  FILE* secret_key = fopen("secret.key","rb");
      TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
      fclose(secret_key);
      int32_t int_answer=0;
      //int32_t int_answer1=0;

        for(int i=0; i<2*BLEN; i++){
            int ai = bootsSymDecrypt(&u_result[i], key)>0;
            int_answer |= (ai<<i);
     // int aj = bootsSymDecrypt(&remainder[i], key)>0;
            //int_answer1 |= (aj<<i);
        }
  
        //printf("\n The 10th index : %d and digit : %d \n", int_answer,int_answer1);
        printf("The result: %d", int_answer);
  //decrypt//

          time_t end_time = clock();

    //printf("......computation of the 16 binary + 32 mux gates took: %ld microsecs\n",end_time-start_time);

    //export the answer to a file (for the cloud)
  	FILE* answer_data = fopen("answer.data","wb");
     	for(int n=0;n<BLEN;n++){
     	 export_gate_bootstrapping_ciphertext_toFile(answer_data, &u_result[n],params);
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
  delete_gate_bootstrapping_ciphertext_array(2, signbit);
  delete_gate_bootstrapping_ciphertext_array(2, signbit1);
  delete_gate_bootstrapping_ciphertext_array(BLEN, result);
  delete_gate_bootstrapping_ciphertext_array(BLEN, result1);
	delete_gate_bootstrapping_ciphertext_array(BLEN, f_result);
  delete_gate_bootstrapping_ciphertext_array(BLEN, u_result);
	delete_gate_bootstrapping_ciphertext_array(BLEN, result_val);
	delete_gate_bootstrapping_ciphertext_array(1, complement);
	delete_gate_bootstrapping_ciphertext_array(1, ans);
  delete_gate_bootstrapping_cloud_keyset(bk);

return 0;

}