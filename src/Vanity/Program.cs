/*
    Vanity: A simple WireGuard vanity public key generator.
    Copyright (C) 2023 Samuel Lucas
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program. If not, see https://www.gnu.org/licenses/.
*/

using System.Text.RegularExpressions;
using System.Globalization;
using System.Diagnostics;
using Geralt;

namespace Vanity;

public static class Program
{
    private const int BenchmarkTrials = 100000;
    
    public static void Main(string[] args)
    {
        Console.WriteLine();
        if (args.Length == 0) {
            DisplayError("Please specify a prefix string.");
        }
        else if (args.Length > 1) {
            DisplayError("Please specify a single prefix string.");
        }
        
        string prefix = args[0];
        if (prefix.Length is < 1 or > 10) {
            DisplayError("Please specify a 1-10 character string.");
        }
        else if (!Regex.IsMatch(prefix, "^[a-zA-Z0-9+/]+$")) {
            DisplayError("Please specify Base64 characters.");
        }
        
        Console.WriteLine($"Searching for \"{prefix}\" in publicKey[..{prefix.Length}], one of every {GetProbability(prefix):N0} keys should match");
        Console.WriteLine($"{BenchmarkTrials:N0} parallel trials takes {TimeTrials()} ms, CPU cores available: {Environment.ProcessorCount}");
        Console.WriteLine("Hit Ctrl+C to stop");
        Parallel.For(0, long.MaxValue, (_, _) =>
        {
            Trial(prefix);
        });
    }
    
    private static long GetProbability(string prefix)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        long alpha = 26 + 10 + 2;
        long nonAlpha = alpha + 26;
        long p = 1;
        foreach (char c in prefix) {
            if (!alphabet.Contains(c)) {
                p *= nonAlpha;
                continue;
            }
            p *= alpha;
        }
        return p;
    }
    
    private static long TimeTrials()
    {
        var stopwatch = new Stopwatch();
        stopwatch.Start();
        Parallel.For(0, BenchmarkTrials, (_, _) =>
        {
            Trial("prefix");
        });
        stopwatch.Stop();
        return stopwatch.ElapsedMilliseconds;
    }
    
    private static void Trial(string prefix)
    {
        Span<byte> publicKey = stackalloc byte[X25519.PublicKeySize], privateKey = stackalloc byte[X25519.PrivateKeySize];
        X25519.GenerateKeyPair(publicKey, privateKey);
        string pk = Encodings.ToBase64(publicKey);
        if (!pk.StartsWith(prefix, ignoreCase: true, CultureInfo.InvariantCulture)) return;
        Console.WriteLine($"private {Encodings.ToBase64(privateKey)}  public {pk}");
    }
    
    private static void DisplayError(string message)
    {
        Console.WriteLine($"Error: {message}");
        Environment.Exit(-1);
    }
}