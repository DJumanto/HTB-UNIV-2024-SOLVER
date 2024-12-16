require_relative "boot"

require "rails/all"
require_relative "../lib/remove_charset_middleware"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

module ContractFrontend
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 7.2

    config.session_store :active_record_store, key: '_contract_frontend_session'
    config.middleware.delete ActionDispatch::RequestId
    config.middleware.delete(Rack::Runtime)
    config.middleware.delete Rack::ETag
    config.autoload_lib(ignore: %w[assets tasks])

    config.paths.add 'lib', eager_load: true

    # Insert middleware
    config.middleware.insert_before Rack::Sendfile, RemoveCharsetMiddleware

    # Don't generate system test files.
    config.generators.system_tests = nil
  end
end
