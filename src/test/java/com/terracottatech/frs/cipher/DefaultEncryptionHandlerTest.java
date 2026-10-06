/*
 * Copyright IBM Corp. 2024, 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.terracottatech.frs.cipher;

import com.terracottatech.frs.GettableAction;
import com.terracottatech.frs.MapActions;
import com.terracottatech.frs.PutAction;
import com.terracottatech.frs.RemoveAction;
import com.terracottatech.frs.action.Action;
import com.terracottatech.frs.action.ActionCodec;
import com.terracottatech.frs.action.ActionCodecImpl;
import com.terracottatech.frs.compaction.CompactionAction;
import com.terracottatech.frs.compaction.CompactionActions;
import com.terracottatech.frs.object.ObjectManager;
import com.terracottatech.frs.object.SimpleObjectManagerEntry;
import com.terracottatech.frs.transaction.TransactionActions;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

@SuppressWarnings("unchecked")
public class DefaultEncryptionHandlerTest {

  // Collection / action IDs that match MapActions and CompactionActions
  private static final int MAP_COLLECTION_ID = 1;
  private static final int COMPACTION_COLLECTION_ID = 2;
  private static final int TRANSACTION_COLLECTION_ID = 3;

  private static final String TOKEN1 = "token1";
  private static final String TOKEN2 = "token2";

  private ObjectManager<ByteBuffer, ByteBuffer, ByteBuffer> objectManager;

  private byte[] key1Bytes;
  private byte[] key2Bytes;

  // Helper data
  private ByteBuffer identifier;
  private ByteBuffer key;
  private ByteBuffer value;

  @Before
  public void setUp() throws Exception {
    objectManager = mock(ObjectManager.class);

    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(256);
    key1Bytes = kg.generateKey().getEncoded();
    key2Bytes = kg.generateKey().getEncoded();

    identifier = buf("identifier");
    key = buf("the-key");
    value = buf("the-value");
  }

  @Test
  public void testGetCurrTokenReturnsConstructorToken() {
    DefaultEncryptionHandler handler = buildHandler(TOKEN1, key1Bytes);
    assertEquals(TOKEN1, handler.getCurrToken());
  }

  @Test
  public void testGetPreviousTokensEmptyOnConstruction() {
    DefaultEncryptionHandler handler = buildHandler(TOKEN1, key1Bytes);
    assertTrue(handler.getPreviousTokens().isEmpty());
  }

  @Test
  public void testIsUsingEncKeyReturnsTrueForConstructorToken() {
    DefaultEncryptionHandler handler = buildHandler(TOKEN1, key1Bytes);
    assertTrue(handler.isUsingEncKey(TOKEN1));
  }

  @Test
  public void testIsUsingEncKeyReturnsFalseForUnknownToken() {
    DefaultEncryptionHandler handler = buildHandler(TOKEN1, key1Bytes);
    assertFalse(handler.isUsingEncKey("unknown"));
  }

  @Test
  public void testAddNewTokenBecomesCurrentAndOldBecomesPresent() {
    DefaultEncryptionHandler handler = buildHandler(TOKEN1, key1Bytes);

    handler.add(TOKEN2, key2Bytes);

    assertEquals(TOKEN2, handler.getCurrToken());
    assertTrue(handler.isUsingEncKey(TOKEN1));
    assertTrue(handler.isUsingEncKey(TOKEN2));
    assertThat(handler.getPreviousTokens(), is(Collections.singletonList(TOKEN1)));
  }

  @Test
  public void testRemoveDropsToken() {
    DefaultEncryptionHandler handler = buildWithTwoTokens();

    handler.remove(Collections.singletonList(TOKEN1));

    assertFalse(handler.isUsingEncKey(TOKEN1));
    assertTrue(handler.isUsingEncKey(TOKEN2));
  }

  @Test
  public void testPutActionEncodeProducesEncryptedPayload() {
    DefaultEncryptionHandler handler = buildHandler(TOKEN1, key1Bytes);
    PutAction put = putAction(-1L);

    ByteBuffer[] encoded = handler.encode(put);

    assertNotNull(encoded);
    assertTrue(encoded.length > 0);

    // The raw concatenated bytes must NOT equal a plain unencrypted encoding
    ByteBuffer[] plainEncoded = plainCodec().encode(put);
    assertThat(flatten(encoded), not(is(flatten(plainEncoded))));
  }

  @Test
  public void testCompactionActionEncodeProducesEncryptedPayload() {
    DefaultEncryptionHandler handler = buildHandler(TOKEN1, key1Bytes);
    CompactionAction compactionAction = compactionAction(105L);

    ByteBuffer[] encoded = handler.encode(compactionAction);

    assertNotNull(encoded);
    assertTrue(encoded.length > 0);

    // The raw concatenated bytes must NOT equal a plain unencrypted encoding
    ByteBuffer[] plainEncoded = plainCodec().encode(compactionAction);
    assertThat(flatten(encoded), not(is(flatten(plainEncoded))));
  }

  @Test
  public void testPutActionRoundTripRestoresKeyAndValue() {
    DefaultEncryptionHandler handler = buildHandler(TOKEN1, key1Bytes);
    PutAction put = putAction(-1L);

    ByteBuffer[] encoded = handler.encode(put);
    Action decoded = handler.decode(encoded);

    assertThat(decoded, instanceOf(GettableAction.class));
    GettableAction got = (GettableAction) decoded;
    assertEquals(key, got.getKey());
    assertEquals(value, got.getValue());
  }

  @Test
  public void testPutActionEncodedWithToken1DecodedWithToken1() {
    DefaultEncryptionHandler handler = buildHandler(TOKEN1, key1Bytes);
    ByteBuffer[] encoded = handler.encode(putAction(-1L));

    // Decode on a fresh handler that also has TOKEN1
    DefaultEncryptionHandler decoder = buildHandler(TOKEN1, key1Bytes);
    GettableAction got = (GettableAction) decoder.decode(encoded);

    assertEquals(key, got.getKey());
    assertEquals(value, got.getValue());
  }

  @Test
  public void testPutActionEncodedWithToken1CanBeDecodedAfterKeyRotation() {
    // Encode with TOKEN1
    DefaultEncryptionHandler handler = buildHandler(TOKEN1, key1Bytes);
    ByteBuffer[] encoded = handler.encode(putAction(-1L));

    // Rotate to TOKEN2 on the same handler — TOKEN1 is still present
    handler.add(TOKEN2, key2Bytes);

    // Decode: the encoded payload carries "token1" inside it; AESCipherManager still has key1
    GettableAction got = (GettableAction) handler.decode(encoded);
    assertEquals(key, got.getKey());
    assertEquals(value, got.getValue());
  }

  @Test
  public void testPutActionEncodedAfterKeyRotationUsesNewToken() {
    DefaultEncryptionHandler handler = buildWithTwoTokens();
    // Current token is TOKEN2
    ByteBuffer[] encoded = handler.encode(putAction(-1L));

    // Decode on a handler that has only TOKEN2
    DefaultEncryptionHandler decoder = buildHandler(TOKEN2, key2Bytes);
    GettableAction got = (GettableAction) decoder.decode(encoded);

    assertEquals(key, got.getKey());
    assertEquals(value, got.getValue());
  }

  @Test
  public void testDecodeWithMissingTokenThrowsAssertionError() {
    // Encode with TOKEN1
    DefaultEncryptionHandler encoder = buildHandler(TOKEN1, key1Bytes);
    ByteBuffer[] encoded = encoder.encode(putAction(-1L));

    // Decoder only has TOKEN2 — TOKEN1 key is absent
    DefaultEncryptionHandler decoder = buildHandler(TOKEN2, key2Bytes);
    Action decoded = decoder.decode(encoded); // decode produces a LazyDecryptingGettableAction

    // Decryption is lazy — it happens on getKey()/getValue()
    GettableAction got = (GettableAction) decoded;
    assertThrows(AssertionError.class, got::getKey);
  }

  @Test
  public void testEachInstanceUsesItsOwnCipherManager() {
    DefaultEncryptionHandler h1 = buildHandler(TOKEN1, key1Bytes);
    DefaultEncryptionHandler h2 = buildHandler(TOKEN2, key2Bytes);

    // Encode same payload on both
    ByteBuffer[] enc1 = h1.encode(putAction(-1L));
    ByteBuffer[] enc2 = h2.encode(putAction(-1L));

    // The encrypted bytes must differ (different keys)
    assertThat(flatten(enc1), not(is(flatten(enc2))));
  }

  @Test
  public void testEncodeDecodeRoundTripForRemoveAction() {
    DefaultEncryptionHandler handler = buildHandler(TOKEN1, key1Bytes);

    // RemoveAction is pass-through — encode via handler must equal encode via raw codec
    // We just verify the bytes are identical to the plain codec output.
    ByteBuffer[] plainRemove = plainCodec().encode(removeAction());

    // Handler must produce identical bytes for a non-encrypted action
    ByteBuffer[] handlerRemove = handler.encode(removeAction());
    assertArrayEquals(flatten(plainRemove).array(), flatten(handlerRemove).array());
  }

  private DefaultEncryptionHandler buildHandler(String token, byte[] keyBytes) {
    ActionCodecImpl codec = new ActionCodecImpl(objectManager);
    DefaultEncryptionHandler encHandler = new DefaultEncryptionHandler(codec, Collections.singletonMap(token, keyBytes), token, true);
    MapActions.registerActions(MAP_COLLECTION_ID, encHandler);
    TransactionActions.registerActions(TRANSACTION_COLLECTION_ID, encHandler);
    CompactionActions.registerActions(COMPACTION_COLLECTION_ID, encHandler);
    return encHandler;
  }

  private ActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> plainCodec() {
    ActionCodecImpl actionCodec = new ActionCodecImpl(objectManager);
    MapActions.registerActions(MAP_COLLECTION_ID, actionCodec);
    TransactionActions.registerActions(TRANSACTION_COLLECTION_ID, actionCodec);
    CompactionActions.registerActions(COMPACTION_COLLECTION_ID, actionCodec);
    return actionCodec;
  }

  private DefaultEncryptionHandler buildWithTwoTokens() {
    Map<String, byte[]> map = new HashMap<>();
    map.put(TOKEN1, key1Bytes);
    map.put(TOKEN2, key2Bytes);
    ActionCodecImpl codec = new ActionCodecImpl(objectManager);
    DefaultEncryptionHandler encHandler = new DefaultEncryptionHandler(codec, map, TOKEN2, true);
    MapActions.registerActions(MAP_COLLECTION_ID, encHandler);
    TransactionActions.registerActions(TRANSACTION_COLLECTION_ID, encHandler);
    CompactionActions.registerActions(COMPACTION_COLLECTION_ID, encHandler);
    return encHandler;
  }

  private PutAction putAction(long invalidatedLsn) {
    return new PutAction(objectManager, null, identifier.duplicate(), key.duplicate(),
        value.duplicate(), invalidatedLsn);
  }

  private CompactionAction compactionAction(long lsn) {
    return new CompactionAction(objectManager, new SimpleObjectManagerEntry<>(identifier.duplicate(),
        key.duplicate(), value.duplicate(), lsn));
  }

  private RemoveAction removeAction() {
    return new RemoveAction(objectManager, null, identifier.duplicate(), key.duplicate(), true);
  }

  private static ByteBuffer buf(String s) {
    return ByteBuffer.wrap(s.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Concatenates all remaining bytes from the buffers into a single ByteBuffer.
   */
  private static ByteBuffer flatten(ByteBuffer[] buffers) {
    int total = Arrays.stream(buffers).mapToInt(ByteBuffer::remaining).sum();
    ByteBuffer out = ByteBuffer.allocate(total);
    for (ByteBuffer b : buffers) out.put(b.duplicate());
    out.flip();
    return out;
  }
}
