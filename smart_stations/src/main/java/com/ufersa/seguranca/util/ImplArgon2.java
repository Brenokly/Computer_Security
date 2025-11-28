package com.ufersa.seguranca.util;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

/**
 * Implementação do Algoritmo Argon2.
 * Variantes: Argon2id (Híbrido de Argon2i e Argon2d).
 * Segurança: Resistente a ataques de GPU/ASIC e Side-Channel.
 */
public class ImplArgon2 {

  private static final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

  /**
   * Gera um hash seguro usando Argon2.
   * Parâmetros configurados conforme Prática 8.2:
   * - Iterações: 4 (Tempo de processamento)
   * - Memória: 65536 KiB (64 MB - Custo de memória para evitar FPGA/ASIC)
   * - Paralelismo: 1 (Threads)
   */
  public static String gerarHash(String senha) {
    try {
      return argon2.hash(4, 65536, 1, senha.toCharArray());
    } finally {
      // Achei isso incrível! Limpa a senha da memória após o uso. ROUBADO!
      argon2.wipeArray(senha.toCharArray());
    }
  }

  // Verifica se a senha corresponde ao hash Argon2 armazenado.
  public static boolean verificarSenha(String hash, String senha) {
    return argon2.verify(hash, senha.toCharArray());
  }
}