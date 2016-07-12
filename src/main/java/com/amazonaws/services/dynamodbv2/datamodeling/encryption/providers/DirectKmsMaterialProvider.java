/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers;

import static com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.WrappedRawMaterials.CONTENT_KEY_ALGORITHM;
import static com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.WrappedRawMaterials.ENVELOPE_KEY;
import static com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.WrappedRawMaterials.KEY_WRAPPING_ALGORITHM;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMappingException;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.SymmetricRawMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.WrappedRawMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.Hkdf;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.amazonaws.util.Base64;
import com.amazonaws.util.VersionInfoUtils;

/**
 * Generates a unique data key for each record in DynamoDB and protects that key
 * using {@link AWSKMS}. Currently, the HashKey, RangeKey, and TableName will be
 * included in the KMS EncryptionContext for wrapping/unwrapping the key. This
 * means that records cannot be copied/moved between tables without re-encryption.
 *
 * @see <a href="http://docs.aws.amazon.com/kms/latest/developerguide/encrypt-context.html">KMS Encryption Context</a>
 */
public class DirectKmsMaterialProvider implements EncryptionMaterialsProvider {
    private static final String VERSION_STRING = "1.0";
    private static final String USER_AGENT = DirectKmsMaterialProvider.class.getName()
            + "/" + VERSION_STRING + "/" + VersionInfoUtils.getVersion();
    private static final String COVERED_ATTR_CTX_KEY = "aws-kms-ec-attr";
    private static final String SIGNING_KEY_ALGORITHM = "amzn-ddb-sig-alg";
    private static final String TABLE_NAME_EC_KEY = "*aws-kms-table*";

    private static final String DEFAULT_ENC_ALG = "AES/256";
    private static final String DEFAULT_SIG_ALG = "HmacSHA256/256";
    private static final String KEY_COVERAGE = "*keys*";
    private static final String KDF_ALG = "HmacSHA256";
    private static final String KDF_SIG_INFO = "Signing";
    private static final String KDF_ENC_INFO = "Encryption";

    private final AWSKMS kms;
    private final String encryptionKeyId;
    private final Map<String, String> description;
    private final String dataKeyAlg;
    private final int dataKeyLength;
    private final String dataKeyDesc;
    private final String sigKeyAlg;
    private final int sigKeyLength;
    private final String sigKeyDesc;

    public DirectKmsMaterialProvider(AWSKMS kms) {
        this(kms, null);
    }

    public DirectKmsMaterialProvider(AWSKMS kms, String encryptionKeyId, Map<String, String> materialDescription) {
        this.kms = kms;
        this.encryptionKeyId = encryptionKeyId;
        this.description = materialDescription != null ?
                Collections.unmodifiableMap(new HashMap<>(materialDescription)) :
                    Collections.<String, String> emptyMap();

        dataKeyDesc = description
                .containsKey(WrappedRawMaterials.CONTENT_KEY_ALGORITHM) ? description
                .get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM) : DEFAULT_ENC_ALG;

        String[] parts = dataKeyDesc.split("/", 2);
        this.dataKeyAlg = parts[0];
        this.dataKeyLength = parts.length == 2 ? Integer.parseInt(parts[1]) : 256;

        sigKeyDesc = description
                .containsKey(SIGNING_KEY_ALGORITHM) ? description
                .get(SIGNING_KEY_ALGORITHM) : DEFAULT_SIG_ALG;

        parts = sigKeyDesc.split("/", 2);
        this.sigKeyAlg = parts[0];
        this.sigKeyLength = parts.length == 2 ? Integer.parseInt(parts[1]) : 256;
    }

    public DirectKmsMaterialProvider(AWSKMS kms, String encryptionKeyId) {
        this(kms, encryptionKeyId, Collections.<String, String> emptyMap());
    }

    @Override
    public DecryptionMaterials getDecryptionMaterials(EncryptionContext context) {
        final Map<String, String> materialDescription = context.getMaterialDescription();

        final Map<String, String> ec = new HashMap<>();
        final String providedEncAlg = materialDescription.get(CONTENT_KEY_ALGORITHM);
        final String providedSigAlg = materialDescription.get(SIGNING_KEY_ALGORITHM);

        ec.put("*" + CONTENT_KEY_ALGORITHM + "*", providedEncAlg);
        ec.put("*" + SIGNING_KEY_ALGORITHM + "*", providedSigAlg);

        populateKmsEcFromEc(context, ec);

        DecryptRequest request = appendUserAgent(new DecryptRequest());
        byte[] ciphertextBlob = Base64.decode(materialDescription.get(ENVELOPE_KEY));
        request.setCiphertextBlob(ciphertextBlob == null ? ByteBuffer.allocate(0) : ByteBuffer.wrap(ciphertextBlob));
        request.setEncryptionContext(ec);
        final DecryptResult decryptResult = kms.decrypt(request);

        final Hkdf kdf;
        try {
            kdf = Hkdf.getInstance(KDF_ALG);
        } catch (NoSuchAlgorithmException e) {
            throw new DynamoDBMappingException(e);
        }
        kdf.init(toArray(decryptResult.getPlaintext()));

        final String[] encAlgParts = providedEncAlg.split("/", 2);
        int encLength = encAlgParts.length == 2 ? Integer.parseInt(encAlgParts[1]) : 256;
        final String[] sigAlgParts = providedSigAlg.split("/", 2);
        int sigLength = sigAlgParts.length == 2 ? Integer.parseInt(sigAlgParts[1]) : 256;

        final SecretKey encryptionKey = new SecretKeySpec(kdf.deriveKey(KDF_ENC_INFO, encLength / 8), encAlgParts[0]);
        final SecretKey macKey = new SecretKeySpec(kdf.deriveKey(KDF_SIG_INFO, sigLength / 8), sigAlgParts[0]);

        return new SymmetricRawMaterials(encryptionKey, macKey, materialDescription);
    }

    @Override
    public EncryptionMaterials getEncryptionMaterials(EncryptionContext context) {
        final Map<String, String> ec = new HashMap<>();
        ec.put("*" + CONTENT_KEY_ALGORITHM + "*", dataKeyDesc);
        ec.put("*" + SIGNING_KEY_ALGORITHM + "*", sigKeyDesc);
        populateKmsEcFromEc(context, ec);

        final GenerateDataKeyRequest req = appendUserAgent(new GenerateDataKeyRequest());
        req.setKeyId(encryptionKeyId);
        req.setNumberOfBytes(256);
        req.setEncryptionContext(ec);

        final GenerateDataKeyResult dataKeyResult = kms.generateDataKey(req);

        final Map<String, String> materialDescription = new HashMap<>();
        materialDescription.putAll(description);
        materialDescription.put(COVERED_ATTR_CTX_KEY, KEY_COVERAGE);
        materialDescription.put(KEY_WRAPPING_ALGORITHM, "kms");
        materialDescription.put(CONTENT_KEY_ALGORITHM, dataKeyDesc);
        materialDescription.put(SIGNING_KEY_ALGORITHM, sigKeyDesc);
        materialDescription.put(ENVELOPE_KEY, Base64.encodeAsString(toArray(dataKeyResult.getCiphertextBlob())));

        final Hkdf kdf;
        try {
            kdf = Hkdf.getInstance(KDF_ALG);
        } catch (NoSuchAlgorithmException e) {
            throw new DynamoDBMappingException(e);
        }

        kdf.init(toArray(dataKeyResult.getPlaintext()));

        final SecretKey encryptionKey = new SecretKeySpec(kdf.deriveKey(KDF_ENC_INFO, dataKeyLength / 8), dataKeyAlg);
        final SecretKey signatureKey = new SecretKeySpec(kdf.deriveKey(KDF_SIG_INFO, sigKeyLength / 8), sigKeyAlg);
        return new SymmetricRawMaterials(encryptionKey, signatureKey, materialDescription);
    }

    /**
     * Extracts relevant information from {@code context} and uses it to populate fields in
     * {@code kmsEc}. Currently, these fields are:
     * <dl>
     * <dt>{@code HashKeyName}</dt>
     * <dd>{@code HashKeyValue}</dd>
     * <dt>{@code RangeKeyName}</dt>
     * <dd>{@code RangeKeyValue}</dd>
     * <dt>{@link #TABLE_NAME_EC_KEY}</dt>
     * <dd>{@code TableName}</dd>
     */
    private static void populateKmsEcFromEc(EncryptionContext context, Map<String, String> kmsEc) {
        final String hashKeyName = context.getHashKeyName();
        if (hashKeyName != null) {
            final AttributeValue hashKey = context.getAttributeValues().get(hashKeyName);
            if (hashKey.getN() != null) {
                kmsEc.put(hashKeyName, hashKey.getN());
            } else if (hashKey.getS() != null) {
                kmsEc.put(hashKeyName, hashKey.getS());
            } else if (hashKey.getB() != null) {
                kmsEc.put(hashKeyName, Base64.encodeAsString(toArray(hashKey.getB())));
            } else {
                throw new UnsupportedOperationException("DirectKmsMaterialProvider only supports String, Number, and Binary HashKeys");
            }
        }
        final String rangeKeyName = context.getRangeKeyName();
        if (rangeKeyName != null) {
            final AttributeValue rangeKey = context.getAttributeValues().get(rangeKeyName);
            if (rangeKey.getN() != null) {
                kmsEc.put(rangeKeyName, rangeKey.getN());
            } else if (rangeKey.getS() != null) {
                kmsEc.put(rangeKeyName, rangeKey.getS());
            } else if (rangeKey.getB() != null) {
                kmsEc.put(rangeKeyName, Base64.encodeAsString(toArray(rangeKey.getB())));
            } else {
                throw new UnsupportedOperationException("DirectKmsMaterialProvider only supports String, Number, and Binary RangeKeys");
            }
        }

        final String tableName = context.getTableName();
        if (tableName != null) {
            kmsEc.put(TABLE_NAME_EC_KEY, tableName);
        }
    }

    private static byte[] toArray(final ByteBuffer buff) {
        final ByteBuffer dup = buff.asReadOnlyBuffer();
        byte[] result = new byte[dup.remaining()];
        dup.get(result);
        return result;
    }

    private final <X extends AmazonWebServiceRequest> X appendUserAgent(final X request) {
        request.getRequestClientOptions().appendUserAgent(USER_AGENT);
        return request;
    }

    @Override
    public void refresh() {
        // No action needed
    }
}
