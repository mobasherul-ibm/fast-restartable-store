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
package com.terracottatech.frs.action;

import com.terracottatech.frs.object.ObjectManager;
import com.terracottatech.frs.util.ByteBufferUtils;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.terracottatech.frs.util.ByteBufferUtils.concatenate;
import static com.terracottatech.frs.util.ByteBufferUtils.getInt;

/**
 * @author tim
 */
public final class ActionCodecImpl<I, K, V> implements ActionCodec<I, K, V> {
  /* ActionCodecImpl.encode
  4 bytes - ActionID.collection
  4 bytes - ActionID.action
  */
  public static final long ACTION_HEADER_OVERHEAD = 8L;

  private static final ActionID NULL_ACTION_ID = new ActionID(-1, -1);

  private final Map<Class<? extends Action>, ActionID> classToId =
          new ConcurrentHashMap<>();
  private final Map<ActionID, ActionHandler<I, K, V, ? extends Action>> idToHandler =
          new ConcurrentHashMap<>();
  private final ObjectManager<I, K, V> objectManager;

  public ActionCodecImpl(ObjectManager<I, K, V> objectManager) {
    this.objectManager = objectManager;
    registerAction(NULL_ACTION_ID, NullAction.class, NullAction.handler());
  }

  private synchronized <T extends Action> void registerAction(ActionID id, Class<? extends Action> actionClass, 
                                                              ActionHandler<I, K, V, T> actionHandler) {
    if (classToId.containsKey(actionClass)) {
      throw new IllegalArgumentException(
          "Action class " + actionClass + " already registered to id " + classToId.get(
              actionClass));
    }
    if (idToHandler.containsKey(id)) {
      throw new IllegalArgumentException(
          "Id " + id + " already registered to action class " + idToHandler.get(id));
    }
    classToId.put(actionClass, id);
    idToHandler.put(id, actionHandler);
  }

  @Override
  public synchronized <T extends Action> void registerAction(int collectionId, int actionId, 
                                                             Class<? extends Action> actionClass, 
                                                             ActionHandler<I, K, V, T> actionHandler) {
    registerAction(new ActionID(collectionId, actionId), actionClass, actionHandler);
  }

  @Override
  public synchronized <T extends Action> void updateHandler(Class<? extends Action> actionClass, 
                                                            ActionHandler<I, K, V, T> actionHandler) {
    if(!classToId.containsKey(actionClass)) {
      throw new IllegalArgumentException("No handler found for: " + actionClass);
    }
    idToHandler.put(classToId.get(actionClass), actionHandler);
  }

  @Override
  public Action decode(ByteBuffer[] buffers) {
    ActionID id = ActionID.withByteBuffers(buffers);
    ActionHandler<I, K, V, ? extends Action> handler = idToHandler.get(id);
    if (handler == null)
      throw new IllegalArgumentException("Unknown Action type id= " + id);
    return handler.decode(objectManager, this, buffers);
  }

  @Override
  public ByteBuffer[] encode(Action action) {
    if (!classToId.containsKey(action.getClass()))
      throw new IllegalArgumentException("Unknown action class " + action.getClass());
    ActionHandler<I, K, V, Action> handler = (ActionHandler<I, K, V, Action>)idToHandler.get(classToId.get(action.getClass()));
    if (handler == null) {
      throw new IllegalStateException("No handler found for " + action.getClass());
    }
    return concatenate(headerBuffer(action), handler.encode(action, this));
  }

  private ByteBuffer headerBuffer(Action action) {
    return classToId.get(action.getClass()).toByteBuffer();
  }

  private static class ActionID {
    private final int collection;
    private final int action;

    private ActionID(int collection, int action) {
      this.collection = collection;
      this.action = action;
    }

    static ActionID withByteBuffers(ByteBuffer[] buffers) {
      if (buffers.length == 0) {
        return NULL_ACTION_ID;
      } else {
        return new ActionID(getInt(buffers), getInt(buffers));
      }
    }

    ByteBuffer toByteBuffer() {
      ByteBuffer buffer = ByteBuffer.allocate(ByteBufferUtils.INT_SIZE * 2);
      buffer.putInt(collection).putInt(action).flip();
      return buffer;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;

      ActionID actionID = (ActionID) o;

      return action == actionID.action && collection == actionID.collection;
    }

    @Override
    public int hashCode() {
      int result = collection;
      result = 31 * result + action;
      return result;
    }

    @Override
    public String toString() {
      return "ActionID{" +
              "collection=" + collection +
              ", action=" + action +
              '}';
    }
  }
}
