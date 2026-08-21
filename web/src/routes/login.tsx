import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { login } from "../gen/jumpgate/auth/v1/auth-AuthService_connectquery";

export function LoginPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const { mutate, isPending, error } = useMutation(login, {
    onSuccess: () => {
      queryClient.invalidateQueries();
      navigate("/");
    },
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    mutate({ email, password, cookieOnly: true });
  }

  return (
    <div>
      <h1>Sign in to jumpgate</h1>
      {error != null && (
        <p role="alert">{error.message}</p>
      )}
      <form onSubmit={handleSubmit}>
        <div>
          <input
            aria-label="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div>
          <input
            aria-label="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit" disabled={isPending}>
          Sign in
        </button>
      </form>
    </div>
  );
}
