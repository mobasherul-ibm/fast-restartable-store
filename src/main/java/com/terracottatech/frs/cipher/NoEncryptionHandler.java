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

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Collections;

public class NoEncryptionHandler implements EncryptedActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> {

  private final ActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> actionCodec;

  public NoEncryptionHandler(ActionCodec<ByteBuffer, ByteBuffer, ByteBuffer> actionCodec) {
    this.actionCodec = actionCodec;
  }

  @Override
  public String getCurrToken() {
    throw new UnsupportedOperationException("operation unsupported");
  }

  @Override
  public Collection<String> getPreviousTokens() {
    return Collections.emptyList();
  }

  @Override
  public boolean isUsingEncKey(String token) {
    return false;
  }

  @Override
  public void add(String token, byte[] key) {
    throw new UnsupportedOperationException("operation unsupported");
  }

  @Override
  public void remove(Collection<String> tokens) {
    throw new UnsupportedOperationException("operation unsupported");
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
