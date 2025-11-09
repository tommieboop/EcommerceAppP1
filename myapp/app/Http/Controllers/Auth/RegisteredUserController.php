<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules;
use Illuminate\View\View;

class RegisteredUserController extends Controller
{
    /**
     * Display the registration view.
     */
    public function create(): View
    {
        return view('auth.register');
    }

    /**
     * Handle an incoming registration request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): RedirectResponse
    {
        // Build validation rules. Captcha rule is added only when a real site key is present.
        $rules = [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', 'unique:'.User::class],
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
        ];

        // Add reCAPTCHA validation only in production and when a non-placeholder site key exists.
        // This avoids blocking local development when the system's CA bundle is not configured
        // (which causes cURL error 60 when Guzzle calls Google's siteverify endpoint).
        $siteKey = env('NOCAPTCHA_SITEKEY');
        if (app()->environment('production') && !empty($siteKey) && $siteKey !== 'your_site_key_here') {
            $rules['g-recaptcha-response'] = ['required', 'captcha'];
        }

        $messages = [
            // (Optional) Add custom error messages
            'g-recaptcha-response.required' => 'Please verify that you are not a robot.',
            'g-recaptcha-response.captcha' => 'The reCAPTCHA check failed. Please try again.',
        ];

        $request->validate($rules, $messages);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        event(new Registered($user));

        Auth::login($user);

        return redirect(route('dashboard', absolute: false));
    }
}
