defmodule Ueberauth.Strategy.Openbank do
  use Ueberauth.Strategy, oauth_module: Ueberauth.Strategy.Openbank.OAuth
  require Logger

  def handle_request!(conn) do
    callback_url = callback_url(conn)

    if String.ends_with?(callback_url, "?"), do: callback_url = String.slice(callback_url, 0..-2)

    module = option(conn, :oauth_module)

    request_token_and_secret = apply(module, :request_token_and_secret, [ callback_url ])

    conn = conn
      |> put_session(:openbank_request_token, request_token_and_secret[:token])
      |> put_session(:openbank_request_token_secret, request_token_and_secret[:token_secret])

    redirect! conn, apply(module, :authorize_url!, [ request_token_and_secret[:token] ])
  end

  def handle_callback!(%Plug.Conn{ params: %{ "oauth_verifier" => oauth_verifier } } = conn) do
    token = conn |> get_session :openbank_request_token
    token_secret = conn |> get_session :openbank_request_token_secret

    module = option(conn, :oauth_module)

    token = apply(module, :get_token!, [token, token_secret, oauth_verifier])

    if token["oauth_token"] == nil do
      [msg | _] = Keyword.keys(token)
      set_errors!(conn, [error("Error", msg)])
    else
      store_token(conn, token)
    end
  end

  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No access token and secret received")])
  end

  def handle_cleanup!(conn) do
    conn
     |> put_session(:openbank_request_token, nil)
     |> put_session(:openbank_request_token_secret, nil)
  end

  defp store_token(conn, token) do
    put_session(conn, :openbank_token, token)
  end

  defp option(conn, key) do
    Dict.get(options(conn), key, Dict.get(default_options, key))
  end
end
