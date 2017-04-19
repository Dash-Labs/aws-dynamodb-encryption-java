/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.amazonaws.services.dynamodbv2.testing;

import java.lang.UnsupportedOperationException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.ResponseMetadata;
import com.amazonaws.regions.Region;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.*;

public class FakeKMS implements AWSKMS {
    private static final SecureRandom rnd = new SecureRandom();
    private static final String ACCOUNT_ID = "01234567890";
    private final Map<DecryptMapKey, DecryptResult> results_ = new HashMap<>();

    @Override
    public CreateAliasResult createAlias(CreateAliasRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public CreateGrantResult createGrant(CreateGrantRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public DeleteImportedKeyMaterialResult deleteImportedKeyMaterial(DeleteImportedKeyMaterialRequest deleteImportedKeyMaterialRequest) {
        throw new UnsupportedOperationException();
    }

    @Override public GetParametersForImportResult getParametersForImport(GetParametersForImportRequest getParametersForImportRequest) {
        throw new UnsupportedOperationException();
    }

    @Override public ImportKeyMaterialResult importKeyMaterial(ImportKeyMaterialRequest importKeyMaterialRequest) {
        throw new UnsupportedOperationException();
    }

    @Override public ListResourceTagsResult listResourceTags(ListResourceTagsRequest listResourceTagsRequest) {
        throw new UnsupportedOperationException();
    }

    @Override public TagResourceResult tagResource(TagResourceRequest tagResourceRequest) {
        throw new UnsupportedOperationException();
    }

    @Override public UntagResourceResult untagResource(UntagResourceRequest untagResourceRequest) {
        throw new UnsupportedOperationException();
    }

    @Override
    public CreateKeyResult createKey() throws AmazonServiceException, AmazonClientException {
        return createKey(new CreateKeyRequest());
    }

    @Override
    public CreateKeyResult createKey(CreateKeyRequest req) throws AmazonServiceException,
            AmazonClientException {
        String keyId = UUID.randomUUID().toString();
        String arn = "arn:aws:testing:kms:" + ACCOUNT_ID + ":key/" + keyId;
        CreateKeyResult result = new CreateKeyResult();
        result.setKeyMetadata(new KeyMetadata().withAWSAccountId(ACCOUNT_ID)
                .withCreationDate(new Date()).withDescription(req.getDescription())
                .withEnabled(true).withKeyId(keyId).withKeyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                .withArn(arn));
        return result;
    }

    @Override
    public DecryptResult decrypt(DecryptRequest req) throws AmazonServiceException,
            AmazonClientException {
        DecryptResult result = results_.get(new DecryptMapKey(req));
        if (result != null) {
            return result;
        } else {
            throw new InvalidCiphertextException("Invalid Ciphertext");
        }
    }

    @Override
    public DeleteAliasResult deleteAlias(DeleteAliasRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public DescribeKeyResult describeKey(DescribeKeyRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public DisableKeyResult disableKey(DisableKeyRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public DisableKeyRotationResult disableKeyRotation(DisableKeyRotationRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public EnableKeyResult enableKey(EnableKeyRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public EnableKeyRotationResult enableKeyRotation(EnableKeyRotationRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public EncryptResult encrypt(EncryptRequest req) throws AmazonServiceException,
            AmazonClientException {
        final byte[] cipherText = new byte[512];
        rnd.nextBytes(cipherText);
        DecryptResult dec = new DecryptResult();
        dec.withKeyId(req.getKeyId()).withPlaintext(req.getPlaintext().asReadOnlyBuffer());
        ByteBuffer ctBuff = ByteBuffer.wrap(cipherText);

        results_.put(new DecryptMapKey(ctBuff, req.getEncryptionContext()), dec);

        return new EncryptResult().withCiphertextBlob(ctBuff).withKeyId(req.getKeyId());
    }

    @Override
    public GenerateDataKeyResult generateDataKey(GenerateDataKeyRequest req)
            throws AmazonServiceException, AmazonClientException {
        byte[] pt;
        if (req.getKeySpec() != null) {
            if (req.getKeySpec().contains("256")) {
                pt = new byte[32];
            } else if (req.getKeySpec().contains("128")) {
                pt = new byte[16];
            } else {
                throw new UnsupportedOperationException();
            }
        } else {
            pt = new byte[req.getNumberOfBytes()];
        }
        rnd.nextBytes(pt);
        ByteBuffer ptBuff = ByteBuffer.wrap(pt);
        EncryptResult encryptResult = encrypt(new EncryptRequest().withKeyId(req.getKeyId())
                .withPlaintext(ptBuff).withEncryptionContext(req.getEncryptionContext()));
        return new GenerateDataKeyResult().withKeyId(req.getKeyId())
                .withCiphertextBlob(encryptResult.getCiphertextBlob()).withPlaintext(ptBuff);

    }

    @Override
    public GenerateDataKeyWithoutPlaintextResult generateDataKeyWithoutPlaintext(
            GenerateDataKeyWithoutPlaintextRequest req) throws AmazonServiceException,
            AmazonClientException {
        GenerateDataKeyResult generateDataKey = generateDataKey(new GenerateDataKeyRequest()
                .withEncryptionContext(req.getEncryptionContext()).withNumberOfBytes(
                        req.getNumberOfBytes()));
        return new GenerateDataKeyWithoutPlaintextResult().withCiphertextBlob(
                generateDataKey.getCiphertextBlob()).withKeyId(req.getKeyId());
    }

    @Override
    public GenerateRandomResult generateRandom() throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public GenerateRandomResult generateRandom(GenerateRandomRequest arg0)
            throws AmazonServiceException, AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ResponseMetadata getCachedResponseMetadata(AmazonWebServiceRequest arg0) {
        throw new UnsupportedOperationException();
    }

    @Override
    public GetKeyPolicyResult getKeyPolicy(GetKeyPolicyRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public GetKeyRotationStatusResult getKeyRotationStatus(GetKeyRotationStatusRequest arg0)
            throws AmazonServiceException, AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ListAliasesResult listAliases() throws AmazonServiceException, AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ListAliasesResult listAliases(ListAliasesRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ListGrantsResult listGrants(ListGrantsRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ListKeyPoliciesResult listKeyPolicies(ListKeyPoliciesRequest arg0)
            throws AmazonServiceException, AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ListKeysResult listKeys() throws AmazonServiceException, AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ListKeysResult listKeys(ListKeysRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public PutKeyPolicyResult putKeyPolicy(PutKeyPolicyRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ReEncryptResult reEncrypt(ReEncryptRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public RetireGrantResult retireGrant() throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public RetireGrantResult retireGrant(RetireGrantRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public RevokeGrantResult revokeGrant(RevokeGrantRequest arg0) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public UpdateAliasResult updateAlias(UpdateAliasRequest req) throws AmazonServiceException,
            AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ScheduleKeyDeletionResult scheduleKeyDeletion(ScheduleKeyDeletionRequest scheduleKeyDeletionRequest)
            throws AmazonServiceException, AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ListRetirableGrantsResult listRetirableGrants(ListRetirableGrantsRequest listRetirableGrantsRequest)
            throws AmazonServiceException, AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public CancelKeyDeletionResult cancelKeyDeletion(CancelKeyDeletionRequest cancelKeyDeletionRequest)
            throws AmazonServiceException, AmazonClientException {
        throw new UnsupportedOperationException();
    }

    @Override @SuppressWarnings("deprecation")
    public void setEndpoint(String arg0) throws IllegalArgumentException {
        // Do nothing
    }

    @Override @SuppressWarnings("deprecation")
    public void setRegion(Region arg0) throws IllegalArgumentException {
        // Do nothing
    }

    @Override
    public void shutdown() {
        // Do nothing
    }

    @Override
    public UpdateKeyDescriptionResult updateKeyDescription(UpdateKeyDescriptionRequest arg0)
            throws AmazonServiceException, AmazonClientException {
        throw new UnsupportedOperationException();
    }

    public void dump() {
        System.out.println(results_);
    }

    public Map<String, String> getSingleEc() {
        if (results_.size() != 1) {
            throw new IllegalStateException("Unexpected number of ciphertexts");
        }
        for (final DecryptMapKey k : results_.keySet()) {
            return k.ec;
        }
        throw new IllegalStateException("Unexpected number of ciphertexts");
    }

    private static class DecryptMapKey {
        private final ByteBuffer cipherText;
        private final Map<String, String> ec;

        public DecryptMapKey(DecryptRequest req) {
            cipherText = req.getCiphertextBlob().asReadOnlyBuffer();
            if (req.getEncryptionContext() != null) {
                ec = Collections.unmodifiableMap(new HashMap<String, String>(req
                        .getEncryptionContext()));
            } else {
                ec = Collections.emptyMap();
            }
        }

        public DecryptMapKey(ByteBuffer ctBuff, Map<String, String> ec) {
            cipherText = ctBuff.asReadOnlyBuffer();
            if (ec != null) {
                this.ec = Collections.unmodifiableMap(new HashMap<String, String>(ec));
            } else {
                this.ec = Collections.emptyMap();
            }
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((cipherText == null) ? 0 : cipherText.hashCode());
            result = prime * result + ((ec == null) ? 0 : ec.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            DecryptMapKey other = (DecryptMapKey) obj;
            if (cipherText == null) {
                if (other.cipherText != null)
                    return false;
            } else if (!cipherText.equals(other.cipherText))
                return false;
            if (ec == null) {
                if (other.ec != null)
                    return false;
            } else if (!ec.equals(other.ec))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return "DecryptMapKey [cipherText=" + cipherText + ", ec=" + ec + "]";
        }
    }
}
