<?php

##########################################################################################
#  SSRF stream wrapper — intercepts http(s):// opens from include()/require()           #
#                                                                                        #
#  uopz_set_hook() cannot hook language constructs (include/require), but PHP lets us   #
#  replace the built-in http/https stream wrappers with a custom class.  When PHP       #
#  evaluates include("http://..."), our wrapper's stream_open() fires first, allowing   #
#  us to log OOB URLs before handing off to the original built-in wrapper.              #
#                                                                                        #
#  Pattern: unregister → log if OOB → restore original → do the open → re-register us  #
##########################################################################################

class __FuzzerSSRFStreamWrapper
{
    /** @var resource|null */
    private $fp;

    /** Required by PHP stream wrapper protocol */
    public $context;

    public function stream_open(string $path, string $mode, int $options, ?string &$opened_path): bool
    {
        if (function_exists('__fuzzer__ssrf_is_oob') && __fuzzer__ssrf_is_oob($path)) {
            if (function_exists('__fuzzer__ssrf_log')) {
                __fuzzer__ssrf_log('include(http)', $path);
            }
        }

        $scheme = (string) parse_url($path, PHP_URL_SCHEME);

        // Temporarily restore the original built-in wrapper to perform the actual open
        stream_wrapper_restore($scheme);
        $this->fp = @fopen($path, $mode);
        // Re-register our wrapper so future opens are also intercepted
        if (in_array($scheme, stream_get_wrappers())) {
            stream_wrapper_unregister($scheme);
        }
        stream_wrapper_register($scheme, '__FuzzerSSRFStreamWrapper');

        return $this->fp !== false;
    }

    public function stream_read(int $count): string|false
    {
        return fread($this->fp, $count);
    }

    public function stream_write(string $data): int
    {
        return fwrite($this->fp, $data);
    }

    public function stream_tell(): int
    {
        return ftell($this->fp);
    }

    public function stream_eof(): bool
    {
        return feof($this->fp);
    }

    public function stream_seek(int $offset, int $whence): bool
    {
        return fseek($this->fp, $offset, $whence) === 0;
    }

    public function stream_stat(): array|false
    {
        return fstat($this->fp);
    }

    public function stream_close(): void
    {
        if (is_resource($this->fp)) {
            fclose($this->fp);
        }
    }

    public function url_stat(string $path, int $flags): array|false
    {
        $scheme = (string) parse_url($path, PHP_URL_SCHEME);
        stream_wrapper_restore($scheme);
        $stat = @stat($path);
        if (in_array($scheme, stream_get_wrappers())) {
            stream_wrapper_unregister($scheme);
        }
        stream_wrapper_register($scheme, '__FuzzerSSRFStreamWrapper');
        return $stat;
    }
}

// Register our wrapper for http and https, replacing the PHP built-ins
foreach (['http', 'https'] as $scheme) {
    if (in_array($scheme, stream_get_wrappers())) {
        stream_wrapper_unregister($scheme);
        stream_wrapper_register($scheme, '__FuzzerSSRFStreamWrapper');
    }
}
