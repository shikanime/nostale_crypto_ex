defmodule NostaleCrypto.Native do
  use Rustler,
      otp_app: :nostale_crypto,
      crate: :nostale_crypto

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
