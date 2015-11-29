
defmodule Ueberauth.Strategy.Openbank.OAuth do
  @defaults [
    site: "https://apisandbox.openbankproject.com",
    request_token_path: "/oauth/initiate",
    authorize_path: "/oauth/authorize",
    access_token_path: "/oauth/token"
  ]

  def credentials(opts \\ []) do
    Application.get_env(:ueberauth, Ueberauth.Strategy.Openbank.OAuth)
      |> Keyword.merge(opts)
      |> OAuther.credentials
  end

  def request_token_and_secret(oauth_callback) do
    request_token_url = @defaults[:site] <> @defaults[:request_token_path]

    params = OAuther.sign("post", request_token_url, [{"oauth_callback", oauth_callback}], credentials)
    {header, req_params} = OAuther.header(params)

    {:ok,
      %HTTPoison.Response{body: body}
    } = HTTPoison.post(request_token_url, "", [header], [{:form, req_params}])

    decoded_body = URI.query_decoder(body) |> Enum.into([])

    [{:token, decoded_body["oauth_token"]}, {:token_secret, decoded_body["oauth_token_secret"]}]
  end

  def authorize_url!(oauth_token) do
    @defaults[:site] <> @defaults[:authorize_path] <> "?oauth_token=" <> oauth_token
  end

  def get_token!(request_token, request_token_secret, oauth_verifier) do
    access_token_url = @defaults[:site] <> @defaults[:access_token_path]
    creds = credentials(token: request_token, token_secret: request_token_secret)

    params = OAuther.sign("post", access_token_url, [{"oauth_verifier", oauth_verifier}], creds)

    {header, req_params} = OAuther.header(params)

    {:ok,
      %HTTPoison.Response{body: body}
      } = HTTPoison.post(access_token_url, "", [header], [{:form, req_params}])

    URI.query_decoder(body) |> Enum.into([])
  end
end
