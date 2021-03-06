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
package com.amazonaws.services.dynamodbv2.datamodeling;

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotEncrypt;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionFlags;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.HandleUnknownAttributes;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.TableAadOverride;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;

/**
 * Encrypts all non-key fields prior to storing them in DynamoDB.
 * 
 * @author Greg Rubin 
 */
public class AttributeEncryptor implements AttributeTransformer {
    private final DynamoDBEncryptor encryptor;
    private final Map<Class<?>, ModelClassMetadata> metadataCache = new ConcurrentHashMap<>();

    public AttributeEncryptor(final DynamoDBEncryptor encryptor) {
        this.encryptor = encryptor;
    }

    public AttributeEncryptor(final EncryptionMaterialsProvider encryptionMaterialsProvider) {
        encryptor = DynamoDBEncryptor.getInstance(encryptionMaterialsProvider);
    }

    public DynamoDBEncryptor getEncryptor() {
        return encryptor;
    }

    @Override
    public Map<String, AttributeValue> transform(final Parameters<?> parameters) {
        // one map of attributeFlags per model class
        final ModelClassMetadata metadata = getModelClassMetadata(parameters);
        try {
            return encryptor.encryptRecord(
                    parameters.getAttributeValues(),
                    metadata.getEncryptionFlags(),
                    paramsToContext(parameters));
        } catch (Exception ex) {
            throw new DynamoDBMappingException(ex);
        }
    }

    @Override
    public Map<String, AttributeValue> untransform(final Parameters<?> parameters) {
        final Map<String, Set<EncryptionFlags>> attributeFlags = getEncryptionFlags(parameters);

        try {
            return encryptor.decryptRecord(
                    parameters.getAttributeValues(),
                    attributeFlags,
                    paramsToContext(parameters));
        } catch (Exception ex) {
            throw new DynamoDBMappingException(ex);
        }
    }

    /*
     * For any attributes we see from DynamoDB that aren't modeled in the mapper class,
     * we either ignore them (the default behavior), or include them for encryption/signing
     * based on the presence of the @HandleUnknownAttributes annotation (unless the class
     * has @DoNotTouch, then we don't include them).
     */
    private Map<String, Set<EncryptionFlags>> getEncryptionFlags(final Parameters<?> parameters) {
        final ModelClassMetadata metadata = getModelClassMetadata(parameters);
        
        // If the class is annotated with @DoNotTouch, then none of the attributes are
        // encrypted or signed, so we don't need to bother looking for unknown attributes.
        if (metadata.getDoNotTouch()) {
            return metadata.getEncryptionFlags();
        }

        final Set<EncryptionFlags> unknownAttributeBehavior = metadata.getUnknownAttributeBehavior();
        final Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<>();
        attributeFlags.putAll(metadata.getEncryptionFlags());
        
        for (final String attributeName : parameters.getAttributeValues().keySet()) {
            if (!attributeFlags.containsKey(attributeName) && 
                    !encryptor.getSignatureFieldName().equals(attributeName) &&
                    !encryptor.getMaterialDescriptionFieldName().equals(attributeName)) {

                attributeFlags.put(attributeName, unknownAttributeBehavior);
            }
        }
        
        return attributeFlags;
    }

    private <T> ModelClassMetadata getModelClassMetadata(Parameters<T> parameters) {
        // Due to the lack of explicit synchronization, it is possible that
        // elements in the cache will be added multiple times. Since they will
        // all be identical, this is okay. Avoiding explicit synchronization
        // means that in the general (retrieval) case, should never block and
        // should be extremely fast.
        final Class<T> clazz = parameters.getModelClass();
        ModelClassMetadata metadata = metadataCache.get(clazz);

        if (metadata == null) {
            Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<>();

            final boolean handleUnknownAttributes = handleUnknownAttributes(clazz);
            final EnumSet<EncryptionFlags> unknownAttributeBehavior = EnumSet.noneOf(EncryptionFlags.class);

            if (shouldTouch(clazz)) {
                StandardBeanProperties.Beans<T> mappings = StandardBeanProperties.of(clazz);

                for (StandardBeanProperties.Bean<T, Object> bean : mappings.map().values()) {
                    final EnumSet<EncryptionFlags> flags = EnumSet.noneOf(EncryptionFlags.class);
                    if (shouldTouch(bean)) {
                        if (shouldEncryptAttribute(clazz, bean)) {
                            flags.add(EncryptionFlags.ENCRYPT);
                        }
                        flags.add(EncryptionFlags.SIGN);
                    }
                    attributeFlags.put(bean.properties().attributeName(), Collections.unmodifiableSet(flags));
                }

                if (handleUnknownAttributes) {
                    unknownAttributeBehavior.add(EncryptionFlags.SIGN);

                    if (shouldEncrypt(clazz)) {
                        unknownAttributeBehavior.add(EncryptionFlags.ENCRYPT);
                    }
                }
            }

            metadata = new ModelClassMetadata(Collections.unmodifiableMap(attributeFlags), doNotTouch(clazz),
                    Collections.unmodifiableSet(unknownAttributeBehavior));
            metadataCache.put(clazz, metadata);
        }
        return metadata;
    }

    /**
     * @return True if {@link DoNotTouch} is not present on the class level. False otherwise
     */
    private boolean shouldTouch(Class<?> clazz) {
        return !doNotTouch(clazz);
    }

    /**
     * @return True if {@link DoNotTouch} is not present on the getter level. False otherwise.
     */
    private <T> boolean shouldTouch(StandardBeanProperties.Bean<T, Object> bean) {
        return !doNotTouch(bean);
    }

    /**
     * @return True if {@link DoNotTouch} IS present on the class level. False otherwise.
     */
    private boolean doNotTouch(Class<?> clazz) {
        return clazz.isAnnotationPresent(DoNotTouch.class);
    }

    /**
     * @return True if {@link DoNotTouch} IS present on the getter level. False otherwise.
     */
    @SuppressWarnings("deprecation")
    private <T> boolean doNotTouch(StandardBeanProperties.Bean<T, Object> bean) {
        return bean.type().getter().isAnnotationPresent(DoNotTouch.class);
    }

    /**
     * @return True if {@link DoNotEncrypt} is NOT present on the class level. False otherwise.
     */
    private boolean shouldEncrypt(Class<?> clazz) {
        return !doNotEncrypt(clazz);
    }

    /**
     * @return True if {@link DoNotEncrypt} IS present on the class level. False otherwise.
     */
    private boolean doNotEncrypt(Class<?> clazz) {
        return clazz.isAnnotationPresent(DoNotEncrypt.class);
    }

    /**
     * @return True if {@link DoNotEncrypt} IS present on the getter level. False otherwise.
     */
    @SuppressWarnings("deprecation")
    private <T> boolean doNotEncrypt(StandardBeanProperties.Bean<T, Object> bean) {
        return bean.type().getter().isAnnotationPresent(DoNotEncrypt.class);
    }

    /**
     * @return True if the attribute should be encrypted, false otherwise.
     */
    private <T> boolean shouldEncryptAttribute(final Class<?> clazz, final StandardBeanProperties.Bean<T, Object> bean) {
        return !(doNotEncrypt(clazz) || doNotEncrypt(bean) || (bean.properties().keyType() != null) || bean.properties().versioned());
    }

    private static EncryptionContext paramsToContext(Parameters<?> params) {
        final Class<?> clazz = params.getModelClass();
        final TableAadOverride override = clazz.getAnnotation(TableAadOverride.class);
        final String tableName = ((override == null) ? params.getTableName() : override.tableName());

        return new EncryptionContext.Builder()
                .withHashKeyName(params.getHashKeyName())
                .withRangeKeyName(params.getRangeKeyName())
                .withTableName(tableName)
                .withModeledClass(params.getModelClass())
                .withAttributeValues(params.getAttributeValues()).build();
    }

    private boolean handleUnknownAttributes(Class<?> clazz) {
        return clazz.getAnnotation(HandleUnknownAttributes.class) != null;
    }

    private static class ModelClassMetadata {
        private final Map<String, Set<EncryptionFlags>> encryptionFlags;
        private final boolean doNotTouch;
        private final Set<EncryptionFlags> unknownAttributeBehavior;

        public ModelClassMetadata(Map<String, Set<EncryptionFlags>> encryptionFlags, 
                boolean doNotTouch, Set<EncryptionFlags> unknownAttributeBehavior) {
            this.encryptionFlags = encryptionFlags;
            this.doNotTouch = doNotTouch;
            this.unknownAttributeBehavior = unknownAttributeBehavior;
        }

        public Map<String, Set<EncryptionFlags>> getEncryptionFlags() {
            return encryptionFlags;
        }

        public boolean getDoNotTouch() {
            return doNotTouch;
        }

        public Set<EncryptionFlags> getUnknownAttributeBehavior() {
            return unknownAttributeBehavior;
        }
    }
}
