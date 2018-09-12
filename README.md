# SHA-256

This is my personal implementation of the SHA-256 specification, released into the public domain.
It is built with two main goals in mind:
 * Being highly predictable and deterministic.
 * Not imposing any requirements on the user.
 
As such it does not perform any runtime allocations nor does it use any exceptions or rtti. Additionally, the interface does not demand the use of STL containers or smart pointers. As a final point, this implementation can trivially be made to not rely on the C++ Standard Library nor the C/C++ runtime. By default the only included libraries are `<cstdint>` and `<cassert>`, both of which can be disabled with their respective macros `BKH_SHA256_NO_CSTDINT` and `BKH_SHA256_NO_CASSERT`. For an example of how to avoid the C/C++ Runtime on Windows check out the example directory.

## Example

Here's a trivial example of using this API.
```cpp
using byte = unsigned char;
  
//Some data
std::vector<byte> vec{ ... };
  
//Compute the digest
byte result[sha256::digest_length];
sha256::compute_hash(vec.data(), vec.size(), result);
```

For an example using the lower level primitive this API provides, please refer to sha256.h.
