require 'thread'
require 'socket'
require 'redis'

# TODO: optional stats
# TODO: performance
# TODO: clean up tests

module Rack

  ##
  # Rack middleware for protecting against Denial-of-service attacks
  # http://en.wikipedia.org/wiki/Denial-of-service_attack.
  #
  # This middleware is designed for small deployments, which most likely
  # are not utilizing load balancing from other software or hardware. Deflect
  # current supports the following functionality:
  #
  # * Saturation prevention (small DoS attacks, or request abuse)
  # * Blacklisting of remote addresses
  # * Whitelisting of remote addresses
  # * Logging
  #
  # === Options:
  #
  #   :log                          When false logging will be bypassed, otherwise pass an object responding to #puts
  #   :log_format                   Alter the logging format
  #   :log_date_format              Alter the logging date format
  #   :request_threshold            Number of requests allowed within the set :interval. Defaults to 100
  #   :interval                     Duration in seconds until the request counter is reset. Defaults to 5
  #   :block_duration               Duration in seconds that a remote address will be blocked. Defaults to 900 (15 minutes)
  #   :whitelist                    Array of remote addresses which bypass Deflect. NOTE: this does not block others
  #   :blacklist                    Array of remote addresses immediately considered malicious
  #   :ignore_agents                a list of words from user agents allow in.
  #   :redis_connection_params      The IP and port of the REDIS server that will be used.
  #   :notifier_callback            A callback that will be used for important notifications.
  #   :fresh_start                  Remove all deflect-related keys from the Redis server before starting up.
  #
  # === Examples:
  #
  #  use Rack::Deflect, :log => $stdout, :request_threshold => 20, :interval => 2, :block_duration => 60
  #
  # CREDIT: TJ Holowaychuk <tj@vision-media.ca>
  #

  class Deflect

    attr_reader :options
    attr_accessor :redis_storage

    def initialize app, options = {}
      @mutex = Mutex.new
      @local_storage_map = {}
      @app, @options = app, {
        :log => false,
        :log_format => "Deflect  %s  %s",
        :log_date_format => '%m/%d/%Y %H:%M:%S',
        :request_threshold => 100,
        :interval => 5,
        :block_duration => 900,
        :whitelist => [],
        :blacklist => [],
        :ignore_agents => [],
        :redis_connection_params => { :host => "127.0.0.1", :port => "6379" },
        :update_config_every => 60,
        :notifier_callback => nil,
        :fresh_start => false
      }.merge(options)
      
      @redis_storage = nil
      @last_updated_config_at = nil
      begin
        @redis_storage = Redis.new(@options[:redis_connection_params]) unless @options[:redis_connection_params].blank?
      rescue Timeout::Error
        # No redis.
      end
      
      if @options[:fresh_start] == true && @redis_storage.present? 
        saved_keys = @redis_storage.keys "Deflector*"
        saved_keys.each { |key_name| @redis_storage.del key_name }
        log "Redis made a FRESH START!"
      end
      
      @request_threshold = options[:request_threshold]
      @interval = options[:interval]
      @block_duration = options[:block_duration]
      @whitelist = options[:whitelist]
      @blacklist = options[:blacklist]
      @ignore_agents = options[:ignore_agents]
      @deflector_enabled = true
      
      update_config_from_redis
    end

    def call env      
      if @ignore_agents.any? {|word| env["HTTP_USER_AGENT"].to_s.downcase.include?(word) }
        log "Skipping user agent #{env["HTTP_USER_AGENT"]}"
        status, headers, body = @app.call env
        [status, headers, body]
      else
        update_config_from_redis
        return deflect! if deflect? env
        status, headers, body = @app.call env
        [status, headers, body]
      end
    end

    # Update configuration from Redis. Note that this is only applicable when using the REDIS storage.
    def update_config_from_redis
      return unless @redis_storage
      return if @last_updated_config_at.present? && Time.now - @last_updated_config_at < @options[:update_config_every]
      
      redis_deflector_enabled = @redis_storage.get("fiverr_config::rack_deflect::enabled")
      if redis_deflector_enabled.present? && (redis_deflector_enabled.downcase == "false" || redis_deflector_enabled.downcase == "no" || redis_deflector_enabled == "0")
        log "*** REDIS says deflector is DISABLED - disabling..." if @deflector_enabled == true
        @deflector_enabled = false
      else
        log "*** REDIS says deflector is ENABLED - enabling..." if @deflector_enabled == false
        @deflector_enabled = true
      end
      
      redis_request_threshold = @redis_storage.get("fiverr_config::rack_deflect::request_threshold")
      if redis_request_threshold.blank?
        @redis_storage.set("fiverr_config::rack_deflect::request_threshold", @request_threshold)
      else
        @request_threshold = redis_request_threshold.to_i
      end
      
      redis_interval = @redis_storage.get("fiverr_config::rack_deflect::interval")
      if redis_interval.blank?
        @redis_storage.set("fiverr_config::rack_deflect::interval", @interval)
      else
        @interval = redis_interval.to_i
      end
      
      redis_block_duration = @redis_storage.get("fiverr_config::rack_deflect::block_duration")
      if redis_block_duration.blank?
        @redis_storage.set("fiverr_config::rack_deflect::block_duration", @block_duration)
      else
        @block_duration = redis_block_duration.to_i
      end
      
      @whitelist = @redis_storage.get("deflector::whitelist") || []
      @whitelist |= @options[:whitelist]
      @blacklist = @redis_storage.get("deflector::blacklist") || []
      @blacklist |= @options[:blacklist]
      @ignore_agents = @redis_storage.get("deflector::ignore_agents") || []
      @ignore_agents |= @options[:ignore_agents]
      
      @last_updated_config_at = Time.now
    end
    
    def deflect!
      [403, { 'Content-Type' => 'text/html', 'Content-Length' => '0' }, []]
    end

    def deflect? env
      @env = env
      @remote_addr = env['REMOTE_ADDR']
      log("Deflector is disabled...") unless @deflector_enabled
      return false unless @deflector_enabled
      log("Deflector is enabled...")
      return false if @whitelist.include? @remote_addr
      return true  if @blacklist.include? @remote_addr
      sync { watch }
    end

    def log message
      return unless options[:log]
      options[:log].puts(options[:log_format] % [Time.now.strftime(options[:log_date_format]), (@redis_storage.nil? ? "(Local)" : "(Redis)") + "  " + message])
    end

    def sync &block
      @mutex.synchronize(&block)
    end

    def watch
      increment_requests
      init_local_storage_map(@remote_addr)
      clear! if watch_expired? and not blocked?
      clear! if blocked? and block_expired?
      block! if watching? and exceeded_request_threshold?
      blocked?
    end

    def block!
      return if blocked?
      block_until = Time.now + @block_duration
      log "NEW BLOCK: blocking #{@remote_addr} until #{block_until.to_s}."
      set_key("block_expires", block_until.to_s)
      notifier = options[:notifier_callback]
      blocked_uris = get_key("requested_uris")
      
      if @redis_storage.present?
        # push the new blocked ip into the 'recently deflected' ip list in redis.
        list_size = @redis_storage.lpush("deflector::recently_deflected_ips", "#{@remote_addr}|#{block_until.to_s}")
        @redis_storage.ltrim("deflector::recently_deflected_ips", 0, 99) if list_size > 100
      end
      
      notifier.call(@remote_addr, Socket.gethostname, blocked_uris) unless notifier.nil?
    end

    def blocked?
      block_expires = get_key("block_expires")
      is_blocked = !(block_expires.nil?)
      if (is_blocked)
        log "BLOCKED: IP #{@remote_addr} is blocked until #{block_expires}."
      end
      is_blocked
    end

    def block_expired?      
      block_expires_str = get_key("block_expires")
      block_has_expired = !(block_expires_str.nil?) && (Time.parse(block_expires_str) < Time.now) rescue false
      if block_has_expired
        log "BLOCK EXPIRED: Block for IP #{@remote_addr} has expired (was blocked until #{block_expires_str})."
      end
      block_has_expired
    end

    def watching?
      get_key('requests').to_i > 0
    end

    def clear!
      return unless watching?
      log "BLOCK RELEASED: released #{@remote_addr}" if blocked?
      clear_for_address(@remote_addr)
    end

    def clear_for_address(address)
      del_key("expires", address)
      del_key("block_expires", address)
      del_key("requests", address)
      del_key("request_uris", address)
    end
    
    def increment_requests
      incr_key("requests")
      log "Current Request: #{@env["REQUEST_URI"]}"
      rrpush("request_uris", "#{@env["REQUEST_METHOD"]} '#{@env["HTTP_HOST"]}#{@env["REQUEST_URI"]}' #{} => #{@env["HTTP_USER_AGENT"]}")
    end

    def exceeded_request_threshold?
      get_key("requests").to_i > @request_threshold
    end

    def watch_expired?
      expired = false;
      expires_str = get_key("expires")
      if expires_str.blank?
        set_key("expires", Time.now + @interval)
      else
        expired = (Time.parse(expires_str) <= Time.now) rescue false
      end
      
      expired     
    end
    
    def init_local_storage_map(addr)
      @local_storage_map[addr] ||= {
        :expires => Time.now + @interval,
        :requests => 0,
        :request_uris => []
      }
    end

    def redis_key(key, addr=@remote_addr)
      "deflector::#{addr}:#{key}"
    end
    
    def set_key(key, val, addr=@remote_addr)
      @local_storage_map[addr.to_sym] = {} if @local_storage_map[addr.to_sym].nil?
      @local_storage_map[addr.to_sym][key.to_sym] = val
      @redis_storage.set(redis_key(key, addr), val) unless @redis_storage.nil?
    end
    
    def get_key(key, addr=@remote_addr)
      val = @redis_storage.get(redis_key(key, addr)) unless @redis_storage.nil?
      val = @local_storage_map[addr.to_sym][key.to_sym] if val.nil? && !(@local_storage_map[addr.to_sym].nil?)
      val
    end
    
    def del_key(key, addr=@remote_addr)
      @local_storage_map[addr.to_sym].delete(key.to_sym) unless @local_storage_map[addr.to_sym].nil?
      @redis_storage.del(redis_key(key, addr)) unless @redis_storage.nil?
    end
    
    def incr_key(key, addr=@remote_addr)
      @local_storage_map[addr.to_sym] = {} if @local_storage_map[addr.to_sym].nil?
      @local_storage_map[addr.to_sym][key.to_sym] = (@local_storage_map[addr.to_sym][key.to_sym].nil? ? 0 : @local_storage_map[addr.to_sym][key.to_sym]) + 1
      @redis_storage.incr(redis_key(key, addr)) unless @redis_storage.nil?
    end
    
    def rrpush(key, val, addr=@remote_addr)
      @local_storage_map[addr.to_sym] = {} if @local_storage_map[addr.to_sym].nil?
      if @local_storage_map[addr.to_sym][key.to_sym]
        @local_storage_map[addr.to_sym][key.to_sym] << val
      else
        @local_storage_map[addr.to_sym][key.to_sym] = [val]
      end
        
      @redis_storage.rpush(redis_key(key, addr), val) unless @redis_storage.nil?
    end
  end
end
