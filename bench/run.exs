defmodule Bench do
  ## Public API

  def login_encrypt() do
    Benchee.run(login_encrypt_jobs(),
      parallel: 8,
      warmup: 1,
      time: 10,
      memory_time: 1,
      pre_check: true,
      load: Path.join(__DIR__, "login_encrypt.benchee"),
      save: [path: Path.join(__DIR__, "login_encrypt.benchee")],
      inputs: login_encrypt_inputs(),
      before_each: fn input -> :binary.copy(input) end
    )
  end

  def login_decrypt() do
    Benchee.run(login_decrypt_jobs(),
      parallel: 8,
      warmup: 1,
      time: 10,
      memory_time: 1,
      pre_check: true,
      load: Path.join(__DIR__, "login_decrypt.benchee"),
      save: [path: Path.join(__DIR__, "login_decrypt.benchee")],
      inputs: login_decrypt_inputs(),
      before_each: fn input -> :binary.copy(input) end
    )
  end

  ## Helpers

  defp login_encrypt_jobs() do
    %{
      "NIF" => &NostaleCrypto.Native.login_encrypt/1,
      "Legacy" => &NostaleCrypto.Legacy.LoginCrypto.encrypt/1
    }
  end

  defp login_decrypt_jobs() do
    %{
      "NIF" => &NostaleCrypto.Native.login_decrypt/1,
      "Legacy" => &NostaleCrypto.Legacy.LoginCrypto.decrypt(&1, nil)
    }
  end

  defp login_encrypt_inputs() do
    [
      {"fail packet", "fail Hello. This is a basic test"}
    ]
  end

  defp login_decrypt_inputs() do
    [
      {"NoS0575 packet",
       <<156, 187, 159, 2, 5, 3, 5, 242, 255, 4, 1, 6, 2, 255, 10, 242, 177, 242, 5, 145, 149, 4,
         0, 5, 4, 4, 5, 148, 255, 149, 2, 144, 150, 2, 145, 2, 4, 5, 149, 150, 2, 3, 145, 6, 1, 9,
         10, 9, 149, 6, 2, 0, 5, 144, 3, 9, 150, 1, 255, 9, 255, 2, 145, 0, 145, 10, 143, 5, 3,
         150, 4, 144, 6, 255, 0, 5, 0, 0, 4, 3, 2, 3, 150, 9, 5, 4, 145, 2, 10, 0, 150, 1, 149, 9,
         1, 144, 6, 150, 9, 4, 145, 3, 9, 255, 5, 4, 0, 150, 148, 9, 10, 148, 150, 2, 255, 143, 9,
         150, 143, 148, 3, 6, 255, 143, 9, 143, 3, 144, 6, 149, 255, 2, 5, 5, 150, 6, 148, 9, 148,
         2, 9, 144, 145, 2, 1, 5, 242, 2, 2, 255, 9, 149, 255, 150, 143, 215, 2, 252, 9, 252, 255,
         252, 255, 2, 3, 1, 242, 2, 242, 143, 3, 150, 0, 5, 2, 255, 144, 150, 0, 5, 3, 148, 5,
         144, 145, 149, 2, 10, 3, 2, 148, 6, 2, 143, 0, 150, 145, 255, 4, 4, 4, 216>>}
    ]
  end
end

Bench.login_encrypt()
Bench.login_decrypt()
