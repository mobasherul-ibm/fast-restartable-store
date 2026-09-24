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

import com.terracottatech.frs.PutAction;
import com.terracottatech.frs.PutActionHandler;
import com.terracottatech.frs.action.ActionCodec;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

public class DefaultEncryptionHandler implements EncryptionHandler {

  private final CipherManager cipherManager;

  public DefaultEncryptionHandler(ActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> codec, Map<String, byte[]> tokenToKeyMap, String currentToken) {
    cipherManager = new AESCipherManager(tokenToKeyMap, currentToken);
    codec.updateHandler(PutAction.class, new EncryptedPutActionHandler(cipherManager, new PutActionHandler()));
  }

  @Override
  public String getCurrToken() {
    return cipherManager.getCurrentToken();
  }

  @Override
  public List<String> getPreviousTokens() {
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
  public void remove(List<String> tokens) {
    cipherManager.remove(tokens);
  }
}
