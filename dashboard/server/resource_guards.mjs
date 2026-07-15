// Dashboard 长时运行资源守卫：提供并发闸门、可延迟关闭的资源生命周期和 WebSocket 背压保护。

// 把环境变量解析为有上下界的整数，非法配置回退到安全默认值。
export function boundedInteger(rawValue, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (rawValue === undefined || rawValue === null
      || (typeof rawValue === "string" && rawValue.trim() === "")) {
    return fallback;
  }
  const parsed = Number(rawValue);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

// 小型非排队并发闸门：达到上限时立即拒绝，避免请求堆积继续占用内存。
export function createConcurrencyGate(limit) {
  const safeLimit = boundedInteger(limit, 1);
  let active = 0;

  return {
    get active() {
      return active;
    },
    get limit() {
      return safeLimit;
    },
    tryAcquire() {
      if (active >= safeLimit) {
        return null;
      }

      active += 1;
      let released = false;
      return () => {
        if (released) {
          return;
        }
        released = true;
        active -= 1;
      };
    }
  };
}

// 资源进入 retiring 后等待其在途操作归零再关闭，避免切换连接时打断正在执行的 RPC。
export function createRetiringResourceTracker(closeResource) {
  const states = new WeakMap();

  function stateFor(resource) {
    let state = states.get(resource);
    if (!state) {
      state = { active: 0, retiring: false, closed: false };
      states.set(resource, state);
    }
    return state;
  }

  function closeIfIdle(resource, state) {
    if (!state.retiring || state.active !== 0 || state.closed) {
      return;
    }
    state.closed = true;
    closeResource(resource);
  }

  return {
    register(resource) {
      stateFor(resource);
      return resource;
    },
    acquire(resource) {
      const state = stateFor(resource);
      if (state.retiring || state.closed) {
        throw new Error("resource is retiring");
      }

      state.active += 1;
      let released = false;
      return () => {
        if (released) {
          return;
        }
        released = true;
        state.active -= 1;
        closeIfIdle(resource, state);
      };
    },
    retire(resource) {
      const state = stateFor(resource);
      state.retiring = true;
      closeIfIdle(resource, state);
    }
  };
}

// connection 回调触发时 socket 已进入 clients 集合；先接管 error，再对超限连接立即硬断开。
export function admitWebSocketConnection(socket, currentConnections, maxConnections) {
  socket.on("error", () => socket.terminate());

  if (currentConnections > maxConnections) {
    socket.terminate();
    return false;
  }

  return true;
}

// 发送前检查单条消息和累计待发送字节；慢客户端直接断开，阻止服务端缓冲区无界增长。
export function sendWebSocketMessage(socket, message, maxBufferedBytes) {
  if (socket.readyState !== 1) {
    return "not-open";
  }

  const queuedBytes = Number(socket.bufferedAmount) || 0;
  const messageBytes = Buffer.byteLength(message);
  if (queuedBytes + messageBytes > maxBufferedBytes) {
    socket.terminate();
    return "terminated";
  }

  try {
    socket.send(message, (error) => {
      if (error && socket.readyState !== 3) {
        socket.terminate();
      }
    });
    return "sent";
  } catch {
    socket.terminate();
    return "terminated";
  }
}
