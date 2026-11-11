"use client";

import { LoginFooter, LoginHeader } from "./login-chrome";
import { LoginForm } from "./login-form";
import { LoginStory } from "./login-story";
import { useDocumentTitle } from "@/i18n/use-document-title";

/**
 * 登录页编排层。
 *
 * 顶栏与页脚共享一条水平基准线，主体为「叙事 + 表单」两栏；
 * 具体状态与交互全部下沉到子组件，本文件不持有任何业务状态。
 */
export default function LoginPage() {
  useDocumentTitle("login.title");

  return (
    <div className="login-page">
      <LoginHeader />
      <main className="login-main">
        <LoginStory />
        <LoginForm />
      </main>
      <LoginFooter />
    </div>
  );
}
