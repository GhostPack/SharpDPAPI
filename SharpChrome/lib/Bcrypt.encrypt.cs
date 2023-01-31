using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpChrome
{
    public partial class BCrypt
    {
        /// <summary>
        /// Encrypts data using the Bcrypt API.
        /// </summary>
        /// <param name="hKey">
        ///     <para>[in, out] hKey: The handle of the key to use to encrypt the data. This handle is obtained from one of the key creation functions, such as BCryptGenerateSymmetricKey, BCryptGenerateKeyPair, or BCryptImportKey.</para>
        /// </param>
        /// <param name="pbInput">
        ///     <para>[in] pbInput: The address of a buffer that contains the plaintext to be encrypted. The cbInput parameter contains the size of the plaintext to encrypt. For more information, see Remarks.</para>
        /// </param>
        /// <param name="cbInput">[in] cbInput: The number of bytes in the pbInput buffer to encrypt.</param>
        /// <param name="pPaddingInfo">[in, optional] pPaddingInfo: A pointer to a structure that contains padding information. This parameter is only used with asymmetric keys and authenticated encryption modes. If an authenticated encryption mode is used, this parameter must point to a BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure. If asymmetric keys are used, the type of structure this parameter points to is determined by the value of the dwFlags parameter. Otherwise, the parameter must be set to NULL.</param>
        /// <param name="pbIV">
        ///     <para>[in, out, optional] pbIV: The address of a buffer that contains the initialization vector (IV) to use during encryption. The cbIV parameter contains the size of this buffer. This function will modify the contents of this buffer. If you need to reuse the IV later, make sure you make a copy of this buffer before calling this function.</para>
        ///     <para>This parameter is optional and can be NULL if no IV is used.</para>
        ///     <para>The required size of the IV can be obtained by calling the BCryptGetProperty function to get the BCRYPT_BLOCK_LENGTH property. This will provide the size of a block for the algorithm, which is also the size of the IV.</para>
        /// </param>
        /// <param name="cbIV">[in] cbIV: The size, in bytes, of the pbIV buffer.</param>
        /// <param name="pbOutput">
        ///     <para>[out, optional] pbOutput: The address of the buffer that receives the ciphertext produced by this function. The cbOutput parameter contains the size of this buffer. For more information, see Remarks.</para>
        ///     <para>If this parameter is NULL, the BCryptEncrypt function calculates the size needed for the ciphertext of the data passed in the pbInput parameter. In this case, the location pointed to by the pcbResult parameter contains this size, and the function returns STATUS_SUCCESS. The pPaddingInfo parameter is not modified.</para>
        ///     <para>If the values of both the pbOutput and pbInput parameters are NULL, an error is returned unless an authenticated encryption algorithm is in use. In the latter case, the call is treated as an authenticated encryption call with zero length data, and the authentication tag is returned in the pPaddingInfo parameter.</para>
        /// </param>
        /// <param name="cbOutput">[in] cbOutput: The size, in bytes, of the pbOutput buffer. This parameter is ignored if the pbOutput parameter is NULL.</param>
        /// <param name="pcbResult">[out] pcbResult: A pointer to a ULONG variable that receives the number of bytes copied to the pbOutput buffer. If pbOutput is NULL, this receives the size, in bytes, required for the ciphertext.</param>
        /// <param name="dwFlags">[in] dwFlags: A set of flags that modify the behavior of this function. The allowed set of flags depends on the type of key specified by the hKey parameter.</param>
        /// <returns></returns>
        [DllImport("BCrypt", SetLastError = true)]
        public static unsafe extern uint BCryptEncrypt(
            SafeKeyHandle hKey,
            byte* pbInput,
            int cbInput,
            void* pPaddingInfo,
            byte* pbIV,
            int cbIV,
            byte* pbOutput,
            int cbOutput,
            out int pcbResult,
            BCryptEncryptFlags dwFlags);
    }
}
