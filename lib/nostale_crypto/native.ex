defmodule NostaleCrypto.Native do
  @moduledoc false

  mix_config = Mix.Project.config()
  version = mix_config[:version]
  github_url = mix_config[:package][:links]["GitHub"]

  use RustlerPrecompiled,
    otp_app: :nostale_crypto,
    crate: "nostale_crypto",
    version: version,
    base_url: "#{github_url}/releases/download/v#{version}",
    force_build: System.get_env("TOKENIZERS_BUILD") in ["1", "true"]

  # Public API

  @spec login_next(binary()) :: {binary() | nil, binary()}
  def login_next(_raw), do: err()

  @spec login_encrypt(String.t()) :: binary()
  def login_encrypt(_raw), do: err()

  @spec login_decrypt(binary()) :: String.t()
  def login_decrypt(_raw), do: err()

  # Helpers

  defp err(), do: :erlang.nif_error(:nif_not_loaded)
end
