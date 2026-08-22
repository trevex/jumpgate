import { useNavigate } from "react-router-dom";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { logout } from "../gen/jumpgate/auth/v1/auth-AuthService_connectquery";
import { useWhoAmI } from "../auth";

export function Shell() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { data } = useWhoAmI();

  const { mutate: doLogout } = useMutation(logout, {
    onSuccess: () => {
      queryClient.clear();
      navigate("/login");
    },
  });

  return (
    <div>
      <header>
        <span>Signed in as {data?.email}</span>
        <button onClick={() => doLogout({})}>Log out</button>
      </header>
      <main>
        <ul aria-label="capabilities">
          {data?.capabilities.map((cap) => (
            <li key={cap}>{cap}</li>
          ))}
        </ul>
      </main>
    </div>
  );
}
