<?php

require 'vendor/autoload.php';

use Goutte\Client;
use Symfony\Component\BrowserKit\Response;
use Symfony\Component\DomCrawler\Crawler;

interface HttpResponseTest
{
    public function evaluate(Response $response);
}

interface CrawlerTest
{
    public function evaluate(Crawler $dom);
}

class TestResult
{
    public $classifcation;
    public $message;

    public static function combine($results)
    {
        $combinedResult = new static;
        $combinedResult->classifcation = TestResultClassification::PASS;
        $combinedResult->messages = [];

        foreach ($results as $result) {
            if ($result->classifcation < $combinedResult->classifcation) {
                $combinedResult->classifcation = $result->classifcation;
            }

            $combinedResult->messages[] = $result->message;
        }

        return $combinedResult;
    }

    public static function fail($message)
    {
        $result = new static;
        $result->classifcation = TestResultClassification::FAIL;
        $result->message = $message;

        return $result;
    }

    public static function warn($message)
    {
        $result = new static;
        $result->classifcation = TestResultClassification::WARN;
        $result->message = $message;

        return $result;
    }

    public static function pass($message)
    {
        $result = new static;
        $result->classifcation = TestResultClassification::PASS;
        $result->message = $message;

        return $result;
    }
}

class TestResultClassification
{
    const PASS = 3;
    const WARN = 2;
    const FAIL = 1;

    public static function toString($classifcation)
    {
        if (self::PASS === $classifcation) {
            return 'pass';
        }

        if (self::WARN === $classifcation) {
            return 'warning';
        }

        if (self::FAIL === $classifcation) {
            return 'failure';
        }
    }
}

class StrictTransportSecurityTest implements HttpResponseTest
{
    public function evaluate(Response $response)
    {
        $header = trim($response->getHeader('Strict-Transport-Security'));

        if ('' === $header) {
            return TestResult::fail('No Strict-Transport-Security header set');
        }

        if (preg_match('{(?:^|;\s*)max-age=([0-9]+)}i', $header, $maxAge)) {
            $maxAge = (int) $maxAge[1];

            if ($maxAge >= 31536000) {
                return TestResult::pass('Strict-Transport-Security set longer than 1 year');
            }

            if ($maxAge >= 15768000) {
                return TestResult::warn('Strict-Transport-Security set between 6 months and 1 year');
            }

            return TestResult::fail(sprintf('Strict-Transport-Securty only set for %u seconds', $maxAge));
        }

        return TestResult::fail('Strict-Transport-Securty is invalid');
    }
}

class FrameOptionsTest implements HttpResponseTest
{
    public function evaluate(Response $response)
    {
        $header = strtolower(trim($response->getHeader('Frame-Options')))
            ?: strtolower(trim($response->getHeader('X-Frame-Options')));

        if ('deny' === $header) {
            return TestResult::pass('X-Frame-Options set to deny');
        }

        if ('sameorigin' === $header) {
            return TestResult::pass('X-Frame-Options set to sameorigin');
        }

        return TestResult::fail('X-Frame-Options is unsafe');
    }
}

class XssProtectionTest implements HttpResponseTest
{
    public function evaluate(Response $response)
    {
        $header = strtolower(trim($response->getHeader('X-XSS-Protection')));

        if ('1; mode=block' === $header) {
            return TestResult::pass('X-XSS-Protection set to blocking mode');
        }

        return TestResult::fail('X-XSS-Protection is unsafe');
    }
}

class ContentTypeOptionsTest implements HttpResponseTest
{
    public function evaluate(Response $response)
    {
        $header = strtolower(trim($response->getHeader('X-Content-Type-Options')));

        if ('nosniff' === $header) {
            return TestResult::pass('X-Content-Type-Options set to prevent sniffing');
        }

        return TestResult::fail('X-Content-Type-Options is unsafe');
    }
}

class MixedContentTest implements CrawlerTest
{
    public function evaluate(Crawler $dom)
    {
        $results = [];

        $results[] = $this->testAttribute($dom, 'src', [
            'img',
            'object',
            'embed',
            'frame',
            'iframe',
            'script',
            'source', // Video/audio
            'track', // Video/audio
        ]);

        $results[] = $this->testAttribute($dom, 'href', [
            'link',
        ]);

        $results[] = $this->testAttribute($dom, 'action', [
            'form',
        ]);

        $results[] = $this->testAttribute($dom, 'formaction', [
            'button',
            'input',
        ]);

        return TestResult::combine($results);
    }

    private function testAttribute(Crawler $dom, $attribute, array $elements)
    {
        $selector = implode(', ', array_map(function ($element) use ($attribute) {
            return sprintf('%s[%s]', $element, $attribute);
        }, $elements));

        $results = $dom->filter($selector)->each(function ($element) use ($attribute) {
            $url = $element->attr($attribute);
            $scheme = parse_url($url, PHP_URL_SCHEME);

            if ('http' === $scheme) {
                return TestResult::fail(sprintf(
                    'Insecure resource used `<%s %s="%s">`',
                    $element->nodeName(),
                    $attribute,
                    $url
                ));
            }
        });

        return TestResult::combine(array_filter($results));
    }
}

class ContentSecurityPolicyTest implements HttpResponseTest
{
    public function evaluate(Response $response)
    {
        $headers = [
            'Content-Security-Policy',
            'Content-Security-Policy-Report-Only',
            'X-Content-Security-Policy',
            'X-WebKit-CSP',
        ];

        $headers = array_map(function ($header) use ($response) {
            return strtolower(trim($response->getHeader($header)));
        }, array_combine($headers, $headers));

        if ('' === implode('', $headers)) {
            return TestResult::fail('No Content Security Policy headers');
        }

        foreach ($headers as $header => $value) {
            if ('' === $value) {
                continue;
            }

            $result = $this->evaluateCsp($value, $header);

            if ('Content-Security-Policy-Report-Only' === $header) {
                $result->classifcation = TestResultClassification::FAIL;
            }

            return $result;
        }

        return TestResult::fail('CSP is unsafe');
    }

    private function evaluateCsp($value, $header)
    {
        $tokens = array_map('trim', explode(';', $value));

        // @todo
        return TestResult::fail('todo');
    }
}

function evaluateHttp($url)
{
    $client = new Client;

    try {
        $crawler = $client->request('GET', $url);
    } catch (\Exception $e) {
        return;
    }

    $response = $client->getResponse();

    $tests = [
        'STS' => new StrictTransportSecurityTest,
        'Frame Options' => new FrameOptionsTest,
        'XSS Protection' => new XssProtectionTest,
        'Content-Type Options' => new ContentTypeOptionsTest,
        'CSP' => new ContentSecurityPolicyTest,
        'Mixed Content' => new MixedContentTest,
    ];

    foreach ($tests as $name => $test) {
        if ($test instanceof HttpResponseTest) {
            $result = $test->evaluate($response);
        } else {
            $result = $test->evaluate($crawler);
        }

        $tests[$name] = $result;
    }

    return $tests;
}

function fetchCertificate($url)
{
    $context = stream_context_create([
        'ssl' => [
            'capture_peer_cert' => true,
        ]
    ]);

    // $socket = stream_socket_client(
    //     sprintf(
    //         'ssl://%s:%u',
    //         parse_url($url, PHP_URL_HOST),
    //         parse_url($url, PHP_URL_PORT) ?: 443
    //     ),
    //     $errorNum,
    //     $errorMsg,
    //     30,
    //     STREAM_CLIENT_CONNECT,
    //     $context
    // );
    //
    // $content = file_get_contents($url, false, $context);
    //
    $socket = fopen($url, 'r', false, $context);

    $params = stream_context_get_params($socket);

    $headers = stream_get_meta_data($socket)['wrapper_data'];

    fclose($socket);

    var_dump($params);
}

$banks = json_decode(file_get_contents(__DIR__.'/banks.json'));

function writeRow($col1, $col2, $coln)
{
    $cols = func_get_args();

    foreach ($cols as $i => $value) {
        switch ($i) {
            case 0:
                $width = 20;
                break;

            default:
                $width = 10;
        }

        $cols[$i] = str_pad($value, $width, ' ', STR_PAD_LEFT);
    }

    fputs(STDOUT, implode(' | ', $cols));
    fputs(STDOUT, "\n");
}

foreach ($banks as $i => $bank) {
    // fetchCertificate($bank->url);

    $results = evaluateHttp($bank->url);

    if ($i === 0) {
        // Write headers before any results.
        $tests = count($results);
        call_user_func_array('writeRow', array_merge(['Bank'], array_keys($results)));
        call_user_func_array('writeRow', array_merge(array_fill(0, $tests + 1, '----')));
    }

    if (!$results) {
        call_user_func_array('writeRow', array_merge([$bank->name], array_fill(0, $tests, 'E')));

        continue;
    }

    call_user_func_array('writeRow', array_merge([$bank->name], array_map(function ($result) {
        switch ($result->classifcation) {
            case TestResultClassification::PASS:
                return '✔';
            case TestResultClassification::FAIL:
                return '✘';
            default:
                return '!';
        }
    }, $results)));
}
