#include <nan.h>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "crypto/equihash.h"
#include "core/difficulty.h"

#include <vector>
using namespace v8;

int verifyEH(const char *hdr, const char *nonceBuff, const std::vector<unsigned char> &soln, unsigned int n = 150, unsigned int k = 5){
  // Hash state
  eh_HashState state;
  //crypto_generichash_blake2b_state state;

  EhInitialiseState(n, k, state);

  blake2b_update(&state, (uint8_t*) hdr, 32);
  blake2b_update(&state, (uint8_t*) nonceBuff, 8);

  //crypto_generichash_blake2b_update(&state, (uint8_t*) hdr, 32);
  //crypto_generichash_blake2b_update(&state, (uint8_t*) nonceBuff, 8);

  bool isValid;
  if (n == 96 && k == 3) {
      isValid = Eh96_3.IsValidSolution(state, soln);
  } else if (n == 150 && k == 5) {
      isValid = Eh150_5.IsValidSolution(state, soln);
  } else if (n == 200 && k == 9) {
      isValid = Eh200_9.IsValidSolution(state, soln);
  //} else if (n == 144 && k == 5) {
  //    isValid = Eh144_5.IsValidSolution(state, soln);
  //} else if (n == 192 && k == 7) {
  //    isValid = Eh192_7.IsValidSolution(state, soln);
  } else if (n == 96 && k == 5) {
      isValid = Eh96_5.IsValidSolution(state, soln);
  } else if (n == 48 && k == 5) {
      isValid = Eh48_5.IsValidSolution(state, soln);
  } else {
      throw std::invalid_argument("Unsupported Equihash parameters");
  }
  return isValid;
}

void Getdiff(const v8::FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  unsigned int diff;
  beam::Difficulty powDiff;

  if (args.Length() < 1) {
  isolate->ThrowException(Exception::TypeError(
    String::NewFromUtf8(isolate, "Wrong number of arguments")));
  return;
  }

  diff = args[0]->Uint32Value();
  powDiff = beam::Difficulty(diff);

  float result = powDiff.ToFloat();
  args.GetReturnValue().Set(result);
}


void DiffCheck(const v8::FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  unsigned int diff;
  beam::Difficulty powDiff;

  if (args.Length() < 2) {
  isolate->ThrowException(Exception::TypeError(
    String::NewFromUtf8(isolate, "Wrong number of arguments")));
  return;
  }

  Local<Object> solnHash = args[0]->ToObject();
  const char *soln = node::Buffer::Data(solnHash);
  diff = args[1]->Uint32Value();
  powDiff = beam::Difficulty(diff);

  beam::uintBig_t<32> hv;
  std::vector<unsigned char> vecSolution(soln, soln + node::Buffer::Length(solnHash));

  Sha256_Onestep(vecSolution, vecSolution.size, hv.m_pData);

  bool targetReached = powDiff.IsTargetReached(hv);

  args.GetReturnValue().Set(targetReached);
}

void Verify(const v8::FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  unsigned int n = 150;
  unsigned int k = 5;

  if (args.Length() < 3) {
  isolate->ThrowException(Exception::TypeError(
    String::NewFromUtf8(isolate, "Wrong number of arguments")));
  return;
  }

  Local<Object> header = args[0]->ToObject();
  Local<Object> nonce = args[1]->ToObject();
  Local<Object> solution = args[2]->ToObject();

  if (args.Length() == 5) {
    n = args[3]->Uint32Value();
    k = args[4]->Uint32Value();
  }

  if(!node::Buffer::HasInstance(header) || !node::Buffer::HasInstance(solution) || !node::Buffer::HasInstance(nonce) ) {
  isolate->ThrowException(Exception::TypeError(
    String::NewFromUtf8(isolate, "Arguments should be buffer objects.")));
  return;
  }

  const char *hdr = node::Buffer::Data(header);
  const char *nonceBuff = node::Buffer::Data(nonce);
  if(node::Buffer::Length(header) != 32) {
	  //invalid hdr length
	  args.GetReturnValue().Set(false);
	  return;
  }
  const char *soln = node::Buffer::Data(solution);

  std::vector<unsigned char> vecSolution(soln, soln + node::Buffer::Length(solution));

  bool result = verifyEH(hdr, nonceBuff, vecSolution, n, k);
  args.GetReturnValue().Set(result);

}


void Init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "verify", Verify);
  NODE_SET_METHOD(exports, "getdiff", Getdiff);
  NODE_SET_METHOD(exports, "diffcheck", DiffCheck);
}

NODE_MODULE(equihashverify, Init)
