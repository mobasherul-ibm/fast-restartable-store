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

import com.terracottatech.frs.DeleteAction;
import com.terracottatech.frs.PutAction;
import com.terracottatech.frs.RemoveAction;
import com.terracottatech.frs.action.Action;
import com.terracottatech.frs.action.ActionCodec;
import com.terracottatech.frs.action.ActionSubCodec;
import com.terracottatech.frs.action.NullAction;
import com.terracottatech.frs.compaction.CompactionAction;
import com.terracottatech.frs.transaction.TransactionCommitAction;
import com.terracottatech.frs.transaction.TransactionalAction;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class EncryptedActionCodecImpl implements EncryptedActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> {

  private static final Map<Class<? extends Action>, EncryptionHandler<?>> ACTION_HANDLERS = new HashMap<>();

  static {
    ACTION_HANDLERS.put(NullAction.class, transparent());
    ACTION_HANDLERS.put(RemoveAction.class, transparent());
    ACTION_HANDLERS.put(DeleteAction.class, transparent());
    ACTION_HANDLERS.put(TransactionalAction.class, transparent());
    ACTION_HANDLERS.put(TransactionCommitAction.class, transparent());

    ACTION_HANDLERS.put(PutAction.class, (codec, cipherManager, collectionId, actionId, actionClass) -> {
      codec.registerAction(99 + collectionId, actionId, PutAction.class, new EncryptedPutActionCodec(cipherManager));
    });

    ACTION_HANDLERS.put(CompactionAction.class, (codec, cipherManager, collectionId, actionId, actionClass) -> {
      codec.registerAction(99 + collectionId, actionId, CompactionAction.class, new EncryptedPutActionCodec(cipherManager));
    });
  }

  private static <T extends Action> EncryptionHandler<T> transparent() {
    return (codec, cipherManager, collectionId, actionId, actionClass) -> {};
  }

  private final CipherManager cipherManager;
  private final ActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> actionCodec;

  public EncryptedActionCodecImpl(ActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> actionCodec,
                                  Map<String, byte[]> tokenToKeyMap, String currentToken) {
    this.cipherManager = new AESCipherManager(tokenToKeyMap, currentToken);
    this.actionCodec = actionCodec;
  }

  @Override
  public String getCurrToken() {
    return cipherManager.getCurrentToken();
  }

  @Override
  public Collection<String> getPreviousTokens() {
    return cipherManager.getPreviousTokens();
  }

  @Override
  public boolean isUsingEncKey(String token) {
    return cipherManager.isUsingEncKey(token);
  }

  @Override
  public void add(String token, byte[] key) {
    cipherManager.add(token, key);
  }

  @Override
  public void remove(Collection<String> tokens) {
    cipherManager.remove(tokens);
  }


  @SuppressWarnings("unchecked")
  @Override
  public <T extends Action> void registerAction(int collectionId, int actionId, Class<T> actionClass,
                                                ActionSubCodec<ByteBuffer, ByteBuffer, ByteBuffer, ? super T> actionSubCodec) {
    actionCodec.registerAction(collectionId, actionId, actionClass, actionSubCodec);
    EncryptionHandler<T> encryptionHandler = (EncryptionHandler<T>) ACTION_HANDLERS.get(actionClass);
    if (encryptionHandler == null) {
      throw new IllegalArgumentException("Encryption has not handler for " + actionClass);
    } else {
      encryptionHandler.handle(actionCodec, cipherManager, collectionId, actionId, actionClass);
    }
  }

  @Override
  public Action decode(ByteBuffer[] buffer) {
    return actionCodec.decode(buffer);
  }

  @Override
  public ByteBuffer[] encode(Action action) {
    return actionCodec.encode(action);
  }

  interface EncryptionHandler<T extends Action> {

    void handle(ActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> codec, CipherManager cipherManager, int collectionId, int actionId,
                Class<T> actionClass);
  }
}
