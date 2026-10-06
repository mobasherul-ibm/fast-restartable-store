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

import com.terracottatech.frs.action.Action;
import com.terracottatech.frs.action.ActionCodec;
import com.terracottatech.frs.action.ActionSubCodec;
import com.terracottatech.frs.config.Configuration;
import com.terracottatech.frs.config.FrsProperty;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class EncryptionManagerImpl implements EncryptionManager<ByteBuffer, ByteBuffer, ByteBuffer> {

  public static final String TOKEN_KEY_DELIMITER = ":";
  public static final String MULTIPLE_TOKEN_KEY_DELIMITER = ",";

  private volatile EncryptedActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> actionCodec;
  private volatile boolean encryptEnabled = false;

  public EncryptionManagerImpl(Configuration configuration,
                               ActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> actionCodec) {
    boolean encrypted = configuration.getBoolean(FrsProperty.STORE_ENCRYPTION_ENABLE);
    if (encrypted) {
      String oldTokenAndKeys = configuration.getString(FrsProperty.STORE_ENCRYPTION_OLD_TOKENS_AND_KEYS);
      String newTokenAndKey = configuration.getString(FrsProperty.STORE_ENCRYPTION_NEW_TOKEN_AND_KEY);
      Map<String, byte[]> tokenToKeyMap = new HashMap<>();

      if (oldTokenAndKeys != null) {
        String[] oldTokensSplit = oldTokenAndKeys.split(MULTIPLE_TOKEN_KEY_DELIMITER);
        for (String s : oldTokensSplit) {
          String[] oldTokenAndKey = s.split(TOKEN_KEY_DELIMITER);
          String oldToken = oldTokenAndKey[0];
          byte[] oldKey = Base64.getDecoder().decode(oldTokenAndKey[1]);
          tokenToKeyMap.put(oldToken, oldKey);
        }
      }

      String[] newTokenSplit = newTokenAndKey.split(TOKEN_KEY_DELIMITER);
      String newToken = newTokenSplit[0];
      byte[] newKey = Base64.getDecoder().decode(newTokenSplit[1]);
      tokenToKeyMap.put(newToken, newKey);

      encryptEnabled = true;
      this.actionCodec = new EncryptedActionCodecImpl(actionCodec, tokenToKeyMap, newToken);
    } else {
      this.actionCodec = new NoEncryptionHandler(actionCodec);
    }
  }

  @Override
  public String getCurrToken() {
    return actionCodec.getCurrToken();
  }

  @Override
  public Collection<String> getPreviousTokens() {
    return actionCodec.getPreviousTokens();
  }

  @Override
  public boolean isUsingEncKey(String token) {
    return actionCodec.isUsingEncKey(token);
  }

  @Override
  public void add(String token, byte[] key) {
    if (encryptEnabled) {
      actionCodec.add(token, key);
    } else {
      actionCodec = new EncryptedActionCodecImpl(actionCodec, Collections.singletonMap(token, key), token);

    }
  }

  @Override
  public void remove(Collection<String> tokens) {
    actionCodec.remove(tokens);
  }


  @Override
  public <T extends Action> void registerAction(int collectionId, int actionId, Class<T> actionClass,
                                                ActionSubCodec<ByteBuffer, ByteBuffer, ByteBuffer, ? super T> actionSubCodec) {
    actionCodec.registerAction(collectionId, actionId, actionClass, actionSubCodec);
  }

  @Override
  public Action decode(ByteBuffer[] buffer) {
    return actionCodec.decode(buffer);
  }

  @Override
  public ByteBuffer[] encode(Action action) {
    return actionCodec.encode(action);
  }
}
