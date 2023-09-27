defmodule NostaleCrypto.MixProject do
  use Mix.Project

  @source_url "https://github.com/imnotavirus/nostale_crypto_ex"
  @version "0.1.0"

  def project do
    [
      app: :nostale_crypto,
      name: "NostaleCrypto",
      description: "TODO",
      version: @version,
      elixir: "~> 1.13",
      deps: deps(),
      package: package()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:rustler, "~> 0.29", optional: true},
      {:rustler_precompiled, "~> 0.7"}
    ]
  end

  defp package do
    [
      files: [
        "lib",
        "native",
        "mix.exs",
        "LICENSE"
      ],
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      maintainers: [""]
    ]
  end
end
