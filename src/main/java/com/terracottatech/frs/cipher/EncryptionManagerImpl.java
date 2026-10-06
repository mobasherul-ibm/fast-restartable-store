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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public class EncryptionManagerImpl implements EncryptionManager<ByteBuffer, ByteBuffer, ByteBuffer> {

  public static final String TOKEN_KEY_DELIMITER = ":";
  public static final String MULTIPLE_TOKEN_KEY_DELIMITER = ",";

  private final ActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> actionCodec;

  private volatile EncryptionHandler<ByteBuffer, ByteBuffer, ByteBuffer> cipherKeyHandler;
  private volatile boolean encryptEnabled = false;
  private final List<ReplayActionRegistration> replayActionRegistrationList = new ArrayList<>();

  public EncryptionManagerImpl(Configuration configuration,
                               ActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> actionCodec) {
    this.actionCodec = actionCodec;
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

      if (newTokenAndKey == null) {
        throw new IllegalArgumentException("token and key must be provided when running with encryption enabled");
      }

      String[] newTokenSplit = newTokenAndKey.split(TOKEN_KEY_DELIMITER);
      String newToken = newTokenSplit[0];
      byte[] newKey = Base64.getDecoder().decode(newTokenSplit[1]);
      tokenToKeyMap.put(newToken, newKey);

      cipherKeyHandler = new DefaultEncryptionHandler(actionCodec, tokenToKeyMap, newToken, true);
      encryptEnabled = true;
    } else {
      cipherKeyHandler = new NoEncryptionHandler(actionCodec);
    }
  }

  @Override
  public String getCurrToken() {
    return cipherKeyHandler.getCurrToken();
  }

  @Override
  public Collection<String> getPreviousTokens() {
    return cipherKeyHandler.getPreviousTokens();
  }

  @Override
  public boolean isUsingEncKey(String token) {
    return cipherKeyHandler.isUsingEncKey(token);
  }

  @Override
  public void add(String token, byte[] key) {
    if (encryptEnabled) {
      cipherKeyHandler.add(token, key);
    } else {
      cipherKeyHandler = new DefaultEncryptionHandler(actionCodec,
          Collections.singletonMap(token, key), token, false);
      for (ReplayActionRegistration r : replayActionRegistrationList) {
        cipherKeyHandler.registerAction(r.collectionId, r.actionId, r.actionClass, r.actionSubCodec);
      }
    }
  }

  @Override
  public void remove(Collection<String> tokens) {
    cipherKeyHandler.remove(tokens);
  }


  @Override
  public <T extends Action> void registerAction(int collectionId, int actionId, Class<T> actionClass,
                                                ActionSubCodec<ByteBuffer, ByteBuffer, ByteBuffer, ? super T> actionSubCodec) {
    cipherKeyHandler.registerAction(collectionId, actionId, actionClass, actionSubCodec);
    replayActionRegistrationList.add(new ReplayActionRegistration(collectionId, actionId, actionClass, actionSubCodec));
  }

  @Override
  public Action decode(ByteBuffer[] buffer) {
    return cipherKeyHandler.decode(buffer);
  }

  @Override
  public ByteBuffer[] encode(Action action) {
    return cipherKeyHandler.encode(action);
  }
  
  private static class ReplayActionRegistration<T extends Action> {

    private final int collectionId;
    private final int actionId;
    private final Class<T> actionClass;
    private final ActionSubCodec<ByteBuffer, ByteBuffer, ByteBuffer, ?> actionSubCodec;

    public ReplayActionRegistration(int collectionId, int actionId, Class<T> actionClass,
                                    ActionSubCodec<ByteBuffer, ByteBuffer, ByteBuffer, ? super T> actionSubCodec) {

      this.collectionId = collectionId;
      this.actionId = actionId;
      this.actionClass = actionClass;
      this.actionSubCodec = actionSubCodec;
    }
  }
}
