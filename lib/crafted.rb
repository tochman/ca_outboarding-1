# frozen_string_literal: true

# require 'omniauth/strategies/oauth2'
require 'omniauth-oauth2'
require 'jwt_validator'
require 'date'

module OmniAuth
  module Strategies
    class CraftedOauth < OmniAuth::Strategies::OAuth2
      option :name, 'crafted_oauth'

      args %i[client_id client_secret domain]

      def client
        options.client_options.site = domain_url
        options.client_options.authorize_url = '/oauth2/authorize'
        options.client_options.token_url = '/oauth2/access_token'
        options.client_options.userinfo_url = '/oauth2/user_info'
        super
      end

      uid { raw_info['sub'] }

      info do
        {
          email: raw_info['email'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          image: image_url
        }
      end

      extra do
        {
          'raw_info' => raw_info,
          'extra_info' => extra_info
        }
      end

      private

      def image_url
        extra_info['profile_image']['image_url_full'] if extra_info['profile_image']['has_image']
      end

      def extra_info
        @extra_info ||= access_token.get('/api/user/v1/accounts').parsed.first
      end

      def raw_info
        @raw_info ||= access_token.get(options.client_options.userinfo_url).parsed
      end

      def callback_url
        if @authorization_code_from_signed_request_in_cookie
          ''
        else
          # Fixes regression in omniauth-oauth2 v1.4.0 by https://github.com/intridea/omniauth-oauth2/commit/85fdbe117c2a4400d001a6368cc359d88f40abc7
          options[:callback_url] || (full_host + script_name + callback_path)
        end
      end

      # Normalize a domain to a URL.
      def domain_url
        domain_url = URI(options.domain)
        domain_url = URI("https://#{domain_url}") if domain_url.scheme.nil?
        domain_url.to_s
      end
    end
  end
end
