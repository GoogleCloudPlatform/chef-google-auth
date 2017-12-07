# Copyright 2017 Google Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Public: Authorizes access to Google API objects.
#
# Examples
#
#   * Uses user credential stored in ~/.config/gcloud
#
#     api = Google::Authorization.new
#         .for!('https://www.googleapis.com/auth/compute.readonly')
#         .from_user_credential!
#         .authorize Google::Apis::ComputeV1::ComputeService.new
#
#   * Uses service account specified by the :file argument (in JSON format)
#
#     api = Google::Authorization.new
#         .for!('https://www.googleapis.com/auth/compute.readonly')
#         .from_service_account_json!(
#             File.join(File.expand_path('~'), "my_account.json"))
#         .authorize Google::Apis::ComputeV1::ComputeService.new
#
# TODO(nelsona): Add support gcloud's beta "app default credential"

require 'googleauth'
require 'json'
require 'net/http'

# Google authorization handler module.
module Google
  # A helper class to determine if we have Ruby 2
  class Ruby
    def self.two?
      Gem::Version.new(RUBY_VERSION.dup) >= Gem::Version.new('2.0.0')
    end

    def self.ensure_two!
      callee = caller(1..1).first[/`([^']*)'/, 1]
      raise "Ruby ~> 2.0.0 required for '#{callee}'" unless Ruby.two?
    end
  end

  require 'google/api_client/client_secrets' if Google::Ruby.two?

  # A class to aquire credentials and authorize Google API calls.
  class Authorization
    LEGACY_CRED_FILE =
      File.join(ENV['HOME'], '.config', 'gcloud', 'credentials').freeze
    CRED_DB_FILE =
      File.join(ENV['HOME'], '.config', 'gcloud', 'credentials.db').freeze
    DEFAULT_APPLICATION_FILE =
      File.join(ENV['HOME'], '.config', 'gcloud',
                'application_default_credentials.json').freeze

    # A helper class to retrieve the machine account token
    class MachineAccount
      METADATA_MASK = ['http://metadata/computeMetadata/v1/instance/',
                       'service-accounts/{{id}}/token'].freeze
      METADATA_HEADER = { key: 'Metadata-Flavor', value: 'Google' }.freeze

      def initialize(account_id)
        raise 'Missing argument for account_id' if account_id.empty?
        @account_id = account_id
        @uri = URI.join(*METADATA_MASK.map do |p|
                          p.gsub('{{id}}', @account_id)
                        end)
        @request = Net::HTTP::Get.new(@uri.request_uri)
        @request[METADATA_HEADER[:key]] = METADATA_HEADER[:value]
      end

      def apply!(result)
        response = Net::HTTP.new(@uri.host, @uri.port).request(@request)
        raise 'Cannot retrieve authentication token from metadata server' \
          unless response.is_a?(Net::HTTPOK)
        result[:authorization] =
          ['Bearer', JSON.parse(response.body)['access_token']].join(' ')
        self
      end
    end

    def initialize
      @authorization = nil
      @scopes = []
    end

    def authorize(obj)
      raise ArgumentError, 'A from_* method needs to be called before' \
        unless @authorization

      if obj.class <= URI::HTTPS || obj.class <= URI::HTTP
        authorize_uri obj
      elsif obj.class < Net::HTTPRequest
        authorize_http obj
      else
        obj.authorization = @authorization
        obj
      end
    end

    def for!(*scopes)
      @scopes = scopes
      self
    end

    def account_id!(account_id)
      @account_id = account_id
      self
    end

    def from_user_credential!
      Google::Ruby.ensure_two! # TODO(nelsona): Ensure we can run with Ruby 1.9
      unless File.exist?(LEGACY_CRED_FILE)
        raise ['Legacy credentials not found and new credentials.db not yet',
               'implemented. For the time being use another provider'].join(' ')
      end
      hash = make_secrets_hash(find_credential)
      @authorization = Google::APIClient::ClientSecrets.new(hash)
                                                       .to_authorization
      self
    end

    def from_service_account_json!(service_account_file)
      raise 'Missing argument for scopes' if @scopes.empty?
      @authorization = Google::Auth::ServiceAccountCredentials.make_creds(
        json_key_io: File.open(service_account_file),
        scope: @scopes
      )
      self
    end

    def from_application_default_credentials!
      unless File.exist?(DEFAULT_APPLICATION_FILE)
        raise ['Application credentials not present.',
               "Run 'gcloud auth application-default login'"].join(' ')
      end
      hash = make_secrets_hash(JSON.parse(File.read(DEFAULT_APPLICATION_FILE)))
      @authorization = Google::APIClient::ClientSecrets.new(hash)
                                                       .to_authorization
      self
    end

    def from_machine_account!
      @authorization = MachineAccount.new(@account_id)
      self
    end

    private

    def authorize_uri(obj)
      http = Net::HTTP.new(obj.host, obj.port)
      http.use_ssl = obj.instance_of?(URI::HTTPS)
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      [http, authorize_http(Net::HTTP::Get.new(obj.request_uri))]
    end

    def authorize_http(req)
      req.extend TokenProperty
      auth = {}
      @authorization.apply!(auth)
      req['Authorization'] = auth[:authorization]
      req.token = auth[:authorization].split(' ')[1]
      req
    end

    def find_credential
      JSON.parse(FILE.read(CREDENTIAL_FILE))['data'].each do |entry|
        if entry['credential']['_class'] == 'OAuth2Credentials'
          return entry['credential']
        end
      end

      raise "Credential not found in '#{file}'"
    end

    def make_secrets_hash(cred)
      {
        'installed' => {
          'client_id' => cred['client_id'],
          'client_secret' => cred['client_secret'],
          'refresh_token' => cred['refresh_token']
        }
      }
    end
  end

  # Extension methods to enable retrieving the authentication token.
  module TokenProperty
    attr_reader :token
    attr_writer :token
  end
end
