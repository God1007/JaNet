// React 应用入口：挂载 Dashboard 根组件并加载全局样式。

import React from "react";
import ReactDOM from "react-dom/client";
import "./styles.css";

// 大体积 Recharts 随 Dashboard 主体异步加载，浏览器可先绘制稳定骨架而不是等待整包解析。
const App = React.lazy(() => import("./App"));

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <React.Suspense fallback={(
      <main className="app-shell" aria-busy="true">
        <section className="skeleton-grid" aria-label="Loading dashboard"><div /><div /><div /></section>
      </main>
    )}>
      <App />
    </React.Suspense>
  </React.StrictMode>
);
